package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/text/language"
)

const (
	egressURL      = "https://ipinfo.io/json"
	egressInterval = 5 * time.Minute
	egressTimeout  = 10 * time.Second
)

type egressLocation struct {
	Country  string
	Timezone string
	Locale   string // Used only when a new account has no language setting.
}

// A separate, credential-free client uses the same explicit proxy setting as
// Google traffic. Empty proxy means direct; redirects and fallback routes are
// not used. The public IP is validated but is neither retained nor logged.
func lookupEgress(parent context.Context, proxy string) (egressLocation, error) {
	ctx, cancel := context.WithTimeout(parent, egressTimeout)
	defer cancel()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	defer tr.CloseIdleConnections()
	if proxy != "" {
		u, err := url.Parse(proxy) // Scheme and host were checked by loadConfig.
		if err != nil {
			return egressLocation{}, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, egressURL, nil)
	if err != nil {
		return egressLocation{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	res, err := client.Do(req)
	if err != nil {
		return egressLocation{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return egressLocation{}, failure("EGRESS_HTTP", "Egress lookup did not return HTTP 200.")
	}
	const limit = 64 << 10
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return egressLocation{}, err
	}
	var answer struct {
		IP       string `json:"ip"`
		Country  string `json:"country"`
		Timezone string `json:"timezone"`
	}
	if len(body) > limit || json.Unmarshal(body, &answer) != nil {
		return egressLocation{}, failure("EGRESS_FORMAT", "Invalid egress metadata.")
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(answer.IP)); err != nil {
		return egressLocation{}, failure("EGRESS_FORMAT", "Invalid egress metadata.")
	}
	zone := strings.TrimSpace(answer.Timezone)
	if zone == "" || zone == "Local" {
		return egressLocation{}, failure("EGRESS_FORMAT", "Egress response has no IANA timezone.")
	}
	if _, err := time.LoadLocation(zone); err != nil {
		return egressLocation{}, failure("EGRESS_FORMAT", "Unknown egress timezone.")
	}
	region, err := language.ParseRegion(strings.TrimSpace(answer.Country))
	if err != nil || !region.IsCountry() {
		return egressLocation{}, failure("EGRESS_FORMAT", "Invalid egress country.")
	}
	likely, _ := language.Compose(language.Und, region)
	base, _ := likely.Base()
	locale, _ := language.Compose(base, region)
	return egressLocation{Country: region.String(), Timezone: zone, Locale: locale.String()}, nil
}

// One account-wide query per interval, including failures. Pages apply the
// observed timezone only at their own idle boundaries, never during a stream.
func (e *engine) readEgress(ctx context.Context) (egressLocation, error) {
	a := e.shared
	select {
	case a.egressGate <- struct{}{}:
	case <-ctx.Done(): return egressLocation{}, ctx.Err()
	}
	defer func() { <-a.egressGate }()
	a.settingsMu.Lock()
	checked, saved, lastErr := a.checked, a.location, a.egressErr
	a.settingsMu.Unlock()
	if !checked.IsZero() && time.Since(checked) < egressInterval {
		e.egressChecked = checked
		return saved, lastErr
	}
	location, err := lookupEgress(ctx, e.config.Proxy)
	if ctx.Err() != nil { return egressLocation{}, ctx.Err() }
	e.egressChecked = time.Now()
	a.settingsMu.Lock()
	a.checked, a.egressErr = e.egressChecked, err
	if err == nil { a.location = location }
	a.settingsMu.Unlock()
	e.audit.record(ctx, "egress", map[string]any{
		"country": location.Country, "timezone": location.Timezone,
		"errorClass": diagnosticError(err),
	})
	if err != nil {
		logLimited(ctx, logWarn, "egress_unavailable", "出口信息查询失败，保留已有配置或回退值", map[string]any{"code": diagnosticError(err)})
	}
	return location, err
}

// Called by the existing maintenance timer and before signing. The same VM lock
// prevents a timezone change during generation. This is not a 403 recovery path.
func (e *engine) refreshEgressLocked(ctx context.Context) error {
	if time.Since(e.egressChecked) < egressInterval {
		return nil
	}
	location, err := e.readEgress(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return nil
	}
	e.egressTimezone = location.Timezone
	if location.Timezone == e.profile.TimeZone {
		return nil
	}
	// An absent/expired VM is already renewed by the caller. Let that single
	// renewal apply the observed timezone instead of creating two VMs.
	if e.vm == nil || e.refreshErr != nil || !time.Now().Before(e.vmExpires) {
		return nil
	}
	updateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err = e.replaceVMLocked(updateCtx)
	cancel()
	if err != nil {
		// The old VM/profile remains intact. Another geographic update may be
		// attempted at the next scheduled check, not on every business request.
		e.egressTimezone = e.profile.TimeZone
		logLimited(ctx, logWarn, "timezone_update_deferred", "时区更新延后，保留当前运行时", map[string]any{"pageId": e.pageID, "code": diagnosticError(err)})
	}
	return ctx.Err()
}
