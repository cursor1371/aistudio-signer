package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	sessionValidationTimeout = 30 * time.Second
	sessionHeadTimeout       = 15 * time.Second
	sessionRedirectLimit     = 5
)

// Evidence contains only HTTP status and redirect classifications, never
// URLs, Location values, identity or credentials. Page access is not API access.
type sessionEvidence struct {
	Stage        string `json:"stage"`
	Method       string `json:"method"`
	Endpoint     string `json:"endpoint"`
	HTTPStatus   int    `json:"httpStatus"`
	ErrorClass   string `json:"errorClass,omitempty"`
	RedirectKind string `json:"redirectKind,omitempty"`
}

type sessionValidationResult struct {
	State       string            `json:"state"`
	Reason      string            `json:"reason"`
	CheckedAt   time.Time         `json:"checkedAt"`
	ElapsedMs   int64             `json:"elapsedMs"`
	AuthUser    int               `json:"authUser"`
	Online      bool              `json:"online"`
	Persistence string            `json:"persistence"`
	Evidence    []sessionEvidence `json:"evidence"`
}

// Validation borrows only immutable account inputs, never a page lease or VM.
// Its requests share the current in-memory cookies and configured transport.
type sessionValidator struct {
	client              *http.Client
	session             *accountSession
	userAgent, language string
	authUser            int
	result              *sessionValidationResult
}

func (x *executor) validateSession(ctx context.Context, params json.RawMessage) (result any, err error) {
	if raw := bytes.TrimSpace(params); len(raw) != 0 {
		var empty struct{}
		if raw[0] != '{' || decode(raw, &empty) != nil {
			return nil, failure("INVALID_INPUT", "validate_session accepts no parameters or an empty object.")
		}
	}
	x.mu.Lock()
	if !x.initialized || x.closed || x.broken.Load() {
		x.mu.Unlock()
		return nil, failure("NOT_INITIALIZED", "Wait for successful initialization before validating the session.")
	}
	root := x.root
	v := sessionValidator{
		client: root.client, session: root.session,
		userAgent: root.userAgent, language: root.language,
		authUser: x.config.AuthUser,
		result: &sessionValidationResult{
			State: "unknown", Reason: "not_checked", AuthUser: x.config.AuthUser,
			Persistence: "not_needed", Evidence: make([]sessionEvidence, 0, 8),
		},
	}
	x.mu.Unlock()
	started := time.Now()
	defer func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			result, err = nil, context.Canceled
			return
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			v.set("unknown", "timeout")
		}
		// Freeze the network observation before persistence: a slow disk must
		// not turn a completed page check into a login or network failure.
		v.result.CheckedAt = time.Now().UTC()
		if v.result.Online {
			// Persistence is account-owned; bound only this check's wait. A
			// slow disk reports deferred without consuming the network budget.
			saveCtx, stopSave := context.WithTimeout(ctx, time.Second)
			v.result.Persistence = v.session.persist(saveCtx)
			stopSave()
		}
		v.result.ElapsedMs = time.Since(started).Milliseconds()
		if errors.Is(ctx.Err(), context.Canceled) {
			result, err = nil, context.Canceled
			return // Set-Cookie is kept, but a cancelled check is not published.
		}
		// The dispatcher resolves an explicit cancel that raced completion and
		// publishes this result once; background persistence never mutates it.
		result = v.result
	}()
	if ctx.Err() != nil {
		return v.result, nil // deferred completion distinguishes timeout from cancellation
	}

	target := studioOrigin + "/apps"
	if v.authUser > 0 {
		target = studioOrigin + "/u/" + strconv.Itoa(v.authUser) + "/apps"
	}
	target += "?authuser=" + strconv.Itoa(v.authUser)
	headCtx, cancel := context.WithTimeout(ctx, sessionHeadTimeout)
	status, _, headErr := v.fetch(headCtx, "head", http.MethodHead, target)
	cancel()
	if headErr != nil {
		v.networkFailure(headErr)
		return v.result, nil
	}

	// Match the browser check: accept normal page access, and confirm auth
	// doubts by GET navigation. An HTTP rejection alone is not expired login.
	switch {
	case status >= 200 && status < 300:
		v.set("valid", "page_accessible")
	case sessionRedirect(status) || status == http.StatusUnauthorized || status == http.StatusForbidden ||
		status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		v.confirmDocument(ctx, target)
	default:
		v.httpFailure(status)
	}
	return v.result, nil
}

func sessionDocumentHeaders(navigation bool) http.Header {
	h := http.Header{}
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Referer", studioOrigin+"/")
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Sec-Fetch-Mode", "cors")
	h.Set("Sec-Fetch-Dest", "empty")
	h.Set("Accept", "*/*")
	if navigation {
		h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		h.Set("Sec-Fetch-Mode", "navigate")
		h.Set("Sec-Fetch-Dest", "document")
		h.Set("Upgrade-Insecure-Requests", "1")
	}
	return h
}

func sessionRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

// Only follow same-application HTTPS redirects. Classify Google sign-in targets
// without requesting them; no HTML parsing, frontend execution or auth RPC.
func (v *sessionValidator) confirmDocument(ctx context.Context, target string) {
	for hop := 0; hop <= sessionRedirectLimit; hop++ {
		status, headers, err := v.fetch(ctx, "navigation", http.MethodGet, target)
		if err != nil {
			v.networkFailure(err)
			return
		}
		if !sessionRedirect(status) {
			if status >= 200 && status < 300 {
				v.set("valid", "page_accessible")
			} else {
				v.httpFailure(status)
			}
			return
		}
		base, _ := url.Parse(target) // all targets are locally constructed or checked below
		location := strings.TrimSpace(headers.Get("Location"))
		next, parseErr := base.Parse(location)
		if parseErr != nil || location == "" || next.Scheme != "https" ||
			next.User != nil || next.Port() != "" && next.Port() != "443" {
			v.set("unknown", "invalid_redirect")
			return
		}
		v.result.Evidence[len(v.result.Evidence)-1].RedirectKind = "other"
		if strings.EqualFold(next.Hostname(), "accounts.google.com") {
			kind := "google_account_flow"
			path := strings.ToLower(next.Path)
			switch {
			case strings.Contains(path, "accountchooser"):
				v.set("unknown", "account_selection_required")
			case strings.Contains(path, "/signin/challenge/"):
				kind = "google_verification"
				v.set("auth_required", "interactive_verification_required")
			case strings.HasPrefix(path, "/servicelogin") || strings.HasPrefix(path, "/interactivelogin") ||
				strings.Contains(path, "/signin"):
				kind = "google_sign_in"
				v.set("auth_required", "sign_in_required")
			default:
				v.set("unknown", "account_flow_required")
			}
			v.result.Evidence[len(v.result.Evidence)-1].RedirectKind = kind
			return // no Cookie or Authorization is sent to this redirect target
		}
		if !strings.EqualFold(next.Hostname(), "aistudio.google.com") {
			v.set("unknown", "redirect_outside_application")
			return
		}
		v.result.Evidence[len(v.result.Evidence)-1].RedirectKind = "aistudio"
		if hop == sessionRedirectLimit {
			v.set("unknown", "redirect_limit")
			return
		}
		q := next.Query()
		if selected := q.Get("authuser"); selected != "" && selected != strconv.Itoa(v.authUser) {
			v.set("unknown", "account_selection_required")
			return
		}
		if path := strings.Split(strings.TrimPrefix(next.Path, "/"), "/"); len(path) >= 2 &&
			path[0] == "u" && path[1] != strconv.Itoa(v.authUser) {
			v.set("unknown", "account_selection_required")
			return
		}
		q.Set("authuser", strconv.Itoa(v.authUser))
		next.RawQuery, next.Fragment = q.Encode(), ""
		target = next.String()
	}
}

// Read headers only. Bodies are closed immediately, so page content, build
// strings and RPC schemas cannot affect classification or hold the check open.
func (v *sessionValidator) fetch(ctx context.Context, stage, method, target string) (
	status int, responseHeaders http.Header, err error,
) {
	evidence := sessionEvidence{Stage: stage, Method: method, Endpoint: "studio_apps"}
	defer func() {
		if err != nil {
			evidence.ErrorClass = sessionValidationError(err)
		}
		v.result.Evidence = append(v.result.Evidence, evidence)
	}()
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header = sessionDocumentHeaders(method == http.MethodGet)
	req.Header.Set("User-Agent", v.userAgent)
	req.Header.Set("Accept-Language", v.language)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	cookie, _, err := v.session.requestCredentials(req.URL, false)
	if err != nil {
		return 0, nil, err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	response, err := v.client.Do(req)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return 0, nil, err
	}
	defer response.Body.Close()
	v.result.Online = true
	evidence.HTTPStatus = response.StatusCode
	v.session.SetCookies(req.URL, response.Cookies())
	return response.StatusCode, response.Header, nil
}

func sessionValidationError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "TIMEOUT"
	}
	return "NETWORK_ERROR"
}

func (v *sessionValidator) set(state, reason string) {
	v.result.State, v.result.Reason = state, reason
}

func (v *sessionValidator) networkFailure(err error) {
	if sessionValidationError(err) == "TIMEOUT" {
		v.set("unknown", "timeout")
	} else {
		v.set("unknown", "network_error")
	}
}

func (v *sessionValidator) httpFailure(status int) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		v.set("unknown", "access_denied")
	case status == http.StatusTooManyRequests:
		v.set("unknown", "rate_limited")
	case status >= 500:
		v.set("unknown", "upstream_unavailable")
	default:
		v.set("unknown", "unexpected_status")
	}
}
