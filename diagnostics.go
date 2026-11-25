package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Diagnostics are opt-in, local stderr observations. Never put credentials,
// request bodies, response bodies or arbitrary error strings in these records.
// Disabled diagnostics do not wrap the transport or read extra account files.
type diagnostics struct {
	mu        sync.Mutex
	output    *logOutput
	resources map[string]resourceCounters
}

type resourceCounters struct {
	Requests  uint64 `json:"requests"`
	HTTP2xx   uint64 `json:"http2xx"`
	HTTP3xx   uint64 `json:"http3xx"`
	HTTP4xx5xx uint64 `json:"http4xx5xx"`
	Errors    uint64 `json:"transportErrors"`
}

type diagnosticOperationKey struct{}
type diagnosticOperation struct {
	id       string
	op       string
	generate atomic.Uint64
}

func newDiagnostics(enabled bool, output *logOutput) *diagnostics {
	if !enabled {
		return nil
	}
	return &diagnostics{output: output, resources: make(map[string]resourceCounters)}
}

func (d *diagnostics) begin(ctx context.Context, cmd command) context.Context {
	// The correlation ID is useful at every level. Detailed collection remains
	// disabled unless a DEBUG diagnostics instance was explicitly created.
	return context.WithValue(ctx, diagnosticOperationKey{}, &diagnosticOperation{id: cmd.ID, op: cmd.Op})
}

func (d *diagnostics) record(ctx context.Context, event string, data any) {
	if d == nil || !d.output.Enabled(logDebug) {
		return
	}
	fields, ok := data.(map[string]any)
	if !ok {
		fields = map[string]any{"details": data}
	}
	d.output.Record(logDebug, event, "运行诊断", operationLogFields(ctx, fields))
}

func diagnosticError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	var local *ipcError
	if errors.As(err, &local) {
		return local.Code
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "NETWORK_TIMEOUT"
	}
	return fmt.Sprintf("%T", err)
}

func diagnosticFields(fields map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Request summaries expose structure and size, never content or its digest.
func diagnosticRequest(r *jsonRequest) map[string]any {
	var gc map[string]json.RawMessage
	_ = json.Unmarshal(alias(r.fields, "generationConfig", "generation_config"), &gc)
	return map[string]any{
		"model": r.model,
		"bodyBytes": len(r.body), "bodyFields": diagnosticFields(r.fields),
		"generationConfigFields": diagnosticFields(gc),
		"contentCount": len(r.contents), "userRounds": r.userRounds(),
		"promptBytes": len(r.prompt), "explicitRerun": r.rerun,
		"functionResultRecognized": r.isFunctionResult,
	}
}

func (d *diagnostics) configuration(ctx context.Context, cfg config) {
	if d == nil {
		return
	}
	proxy := "direct"
	if parsed, err := url.Parse(cfg.Proxy); err == nil && cfg.Proxy != "" {
		proxy = parsed.Scheme
	}
	d.record(ctx, "configuration", map[string]any{
		"bootstrapModel": "models/" + cfg.Model, "authUser": cfg.AuthUser,
		"locale": cfg.Locale, "timezone": cfg.Timezone,
		"proxyMode": proxy, "systemProxyUsed": false,
		"initTimeoutSeconds": cfg.InitTimeoutSeconds, "signTimeoutSeconds": cfg.SignTimeoutSeconds,
		"generationDeadline": false,
		"pageStorageSupported": true, "resourceCacheSupported": true,
		"cookieSelection": "ordered-state", "inheritSavedSettings": cfg.Locale == "" || cfg.Timezone == "",
		"authRecoveryEnabled": false, "businessReplayEnabled": false,
	})
}

func (d *diagnostics) sessionState(ctx context.Context, phase string, session *accountSession) {
	if d == nil || session == nil {
		return
	}
	session.mu.Lock()
	count, localStorageCount := len(session.cookies), len(session.storage)
	_, loggingCached := session.pageStorage["ais_glcr"]
	pageItems, pageLoaded := len(session.pageStorage), session.storageLoaded
	session.mu.Unlock()
	selected := make(map[string]any, 3)
	for name, address := range map[string]string{
		"studio": studioOrigin + "/", "waa": waaCreateURL, "generate": generateURL,
	} {
		u, _ := url.Parse(address)
		selected[name] = diagnosticCookies(session.Cookies(u))
	}
	d.record(ctx, "session", map[string]any{
		"phase": phase, "storedCookieCount": count,
		"localStorageCount": localStorageCount, "loggingCachePresent": loggingCached,
		"separatePageStorageLoaded": pageLoaded, "pageStorageEntries": pageItems,
		"cookieSelection": "ordered-state",
		"selectedCookies": selected,
	})
}

func diagnosticCookies(cookies []*http.Cookie) map[string]any {
	names := make([]string, 0, len(cookies))
	counts := make(map[string]int)
	present := map[string]bool{"SAPISID": false, "__Secure-1PAPISID": false, "__Secure-3PAPISID": false}
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
		counts[cookie.Name]++
		if _, needed := present[cookie.Name]; needed && cookie.Value != "" {
			present[cookie.Name] = true
		}
	}
	duplicates := 0
	for _, count := range counts {
		duplicates += max(count-1, 0)
	}
	return map[string]any{"count": len(cookies), "namesInOrder": names, "duplicateNames": duplicates, "authCookiePresent": present}
}

// Observes the headers after do() has attached the ordered account cookies.
// No header values containing credentials are copied into diagnostic output.
func diagnosticHeaders(req *http.Request) map[string]any {
	segments := map[string]bool{"SAPISIDHASH": false, "SAPISID1PHASH": false, "SAPISID3PHASH": false}
	for _, word := range strings.Fields(req.Header.Get("Authorization")) {
		if _, known := segments[word]; known {
			segments[word] = true
		}
	}
	var authUser any
	if value, err := strconv.Atoi(req.Header.Get("X-Goog-AuthUser")); err == nil {
		authUser = value
	}
	tier := req.Header.Get("X-AIStudio-G1-Tier")
	if tier != "" && tier != "TIER0" && tier != "TIER1" && tier != "TIER2" {
		tier = "other"
	}
	return map[string]any{
		"contentType": req.Header.Get("Content-Type"), "authorizationSegments": segments,
		"authUser": authUser, "benefitTier": tier,
		"apiKeyPresent": req.Header.Get("X-Goog-Api-Key") != "",
		"visitPresent": req.Header.Get("X-AIStudio-Visit-Id") != "",
		"loggingContextPresent": req.Header.Get("X-Goog-Ext-519733851-bin") != "",
		"userAgentPresent": req.Header.Get("User-Agent") != "",
		"acceptLanguage": req.Header.Get("Accept-Language"),
		"priority": req.Header.Get("Priority"),
		"cookies": diagnosticCookies(req.Cookies()),
	}
}

type diagnosticTransport struct {
	next http.RoundTripper
	d    *diagnostics
}

func diagnosticTarget(req *http.Request) string {
	if req.URL.Scheme == "https" && req.URL.Host == "alkalimakersuite-pa.clients6.google.com" {
		prefix := "/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/"
		if method, ok := strings.CutPrefix(req.URL.Path, prefix); ok {
			switch method {
			case "GenerateContent", "GetAiStudioBenefitTier", "GetLoggingContext", "ListModels", "CountTokens":
				return method
			}
		}
	}
	if req.URL.Scheme == "https" && req.URL.Host == "waa-pa.clients6.google.com" {
		return "Waa"
	}
	return "resource"
}

func diagnosticResource(req *http.Request) string {
	switch dest := req.Header.Get("Sec-Fetch-Dest"); dest {
	case "document", "script", "style", "image", "iframe":
		return dest
	default:
		return "other"
	}
}

func (t *diagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	kind := diagnosticTarget(req)
	var call uint64
	if kind == "GenerateContent" {
		if op, _ := req.Context().Value(diagnosticOperationKey{}).(*diagnosticOperation); op != nil {
			call = op.generate.Add(1)
		}
		t.d.record(req.Context(), "http_request", map[string]any{
			"method": kind, "call": call, "scope": "round_tripper_handoff",
			"ct": req.URL.Query().Get("$ct"), "alt": req.URL.Query().Get("alt"),
			"headers": diagnosticHeaders(req),
		})
	}
	started := time.Now()
	response, err := t.next.RoundTrip(req)
	status, protocol := 0, ""
	if response != nil {
		status, protocol = response.StatusCode, response.Proto
	}
	if kind == "resource" {
		t.d.mu.Lock()
		key := diagnosticResource(req)
		count := t.d.resources[key]
		count.Requests++
		switch {
		case err != nil:
			count.Errors++
		case status >= 200 && status < 300:
			count.HTTP2xx++
		case status >= 300 && status < 400:
			count.HTTP3xx++
		case status >= 400:
			count.HTTP4xx5xx++
		}
		t.d.resources[key] = count
		t.d.mu.Unlock()
	} else {
		t.d.record(req.Context(), "http_headers", map[string]any{
			"method": kind, "call": call, "scope": "round_tripper_handoff",
			"status": status, "protocol": protocol, "untilHeadersMs": time.Since(started).Milliseconds(),
			"errorClass": diagnosticError(err),
		})
	}
	return response, err
}

func (t *diagnosticTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *diagnosticTransport) Close() error {
	if closer, ok := t.next.(io.Closer); ok {
		return closer.Close()
	}
	t.CloseIdleConnections()
	return nil
}

func (d *diagnostics) resourcesSnapshot() map[string]resourceCounters {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	copy := make(map[string]resourceCounters, len(d.resources))
	for key, value := range d.resources {
		copy[key] = value
	}
	return copy
}

var diagnosticBuildPattern = regexp.MustCompile(`boq-makersuite\.(MakerSuite\.[A-Za-z0-9_.-]+)`)

func (d *diagnostics) pageBuild(ctx context.Context, body []byte) {
	if d == nil {
		return
	}
	build := "unresolved"
	if found := diagnosticBuildPattern.FindSubmatch(body); len(found) == 2 {
		build = string(found[1])
	}
	d.record(ctx, "page_build", map[string]any{"build": build, "htmlBytes": len(body)})
}

