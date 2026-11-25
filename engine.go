package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/gofrs/flock"
	"local/aistudio-signer/transport"
	"local/aistudio-signer/waa"
	"local/aistudio-signer/waa/prooftime"
	"local/aistudio-signer/waa/rhythm"
)

const (
	makerRPC    = "https://alkalimakersuite-pa.clients6.google.com/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/"
	jsonQuery   = "?%24ct=application%2Fjson&alt=json"
	generateURL = makerRPC + "GenerateContent" + jsonQuery
	benefitURL  = makerRPC + "GetAiStudioBenefitTier" + jsonQuery
	vmLifetime  = 12 * time.Hour
)

type config struct {
	StorageState       string `json:"storage_state"`
	Model              string `json:"model"`
	AuthUser           int    `json:"auth_user"`
	Proxy              string `json:"proxy"`
	Locale             string `json:"locale"`
	Timezone           string `json:"timezone"`
	InitTimeoutSeconds int    `json:"init_timeout_seconds"`
	SignTimeoutSeconds int    `json:"sign_timeout_seconds"`
	Capacity           int    `json:"capacity"`
}

func loadConfig(path string) (config, error) {
	cfg := config{
		InitTimeoutSeconds: 120, SignTimeoutSeconds: 30, Capacity: 1,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, failure("INVALID_CONFIG", "Cannot read configuration file.")
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return cfg, failure("INVALID_CONFIG", "Configuration must be a JSON object.")
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return cfg, failure("INVALID_CONFIG", "Configuration values cannot be null; omit optional values to use defaults.")
		}
	}
	if err = decode(raw, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Capacity < 1 {
		return cfg, failure("INVALID_CONFIG", "capacity must be a positive integer.")
	}
	cfg.Model = strings.TrimPrefix(cfg.Model, "models/")
	if cfg.StorageState == "" || !modelPattern.MatchString("models/"+cfg.Model) || cfg.AuthUser < 0 {
		return cfg, failure("INVALID_CONFIG", "Invalid storage_state, model or auth_user.")
	}
	if cfg.InitTimeoutSeconds < 1 || cfg.InitTimeoutSeconds > 600 ||
		cfg.SignTimeoutSeconds < 1 || cfg.SignTimeoutSeconds > 3600 {
		return cfg, failure("INVALID_CONFIG", "Invalid timeout configuration.")
	}
	if cfg.Proxy != "" {
		p, err := url.Parse(cfg.Proxy)
		if err != nil || p.Hostname() == "" ||
			(p.Scheme != "http" && p.Scheme != "https" && p.Scheme != "socks5") {
			return cfg, failure("INVALID_CONFIG", "Unsupported proxy URL.")
		}
	}
	cfg.Locale, cfg.Timezone = strings.TrimSpace(cfg.Locale), strings.TrimSpace(cfg.Timezone)
	if cfg.Timezone != "" {
		if _, err = time.LoadLocation(cfg.Timezone); err != nil {
			return cfg, failure("INVALID_CONFIG", "Unknown timezone.")
		}
	}
	if !filepath.IsAbs(cfg.StorageState) {
		cfg.StorageState = filepath.Join(filepath.Dir(path), cfg.StorageState)
	}
	cfg.StorageState, err = filepath.Abs(cfg.StorageState)
	return cfg, err
}

type emitFunc func(string, any) error

// One engine is one leased page. Its VM lock is never shared with other pages.
type engine struct {
	shared      *accountRuntime
	pageID      int
	closeOnce   sync.Once
	closeErr    error
	audit       *diagnostics
	config      config
	lifetime    context.Context
	cancel      context.CancelFunc
	client      *http.Client
	session     *accountSession
	lock        *flock.Flock
	initialized bool
	broken      bool
	profile     waa.Profile
	fingerprint *accountProfile
	egressChecked time.Time
	egressTimezone string
	rhythm      rhythm.Rhythm
	pointer     *waa.Pointer
	userAgent   string
	language    string
	pageURL     string
	apiKey      string
	visitID     string
	logHeader      string
	pageLoaded     time.Time
	loggingMaxAge  int64
	cacheDirectory string
	pageCache   *pageCache
	page        pageState
	background sync.WaitGroup

	// Renewal cannot replace a VM while a protected request is using it.
	vmMu            pageMutex
	vm              *waa.Runtime
	vmExpires       time.Time
	refreshTimer    *time.Timer
	refreshSequence uint64 // vmMu-owned; invalidates callbacks that already fired
	refreshErr      error
	closed          bool
	interpreterHash string
	interpreter     string

	tier        string
	tierExpires time.Time
	tierStatus  string
}

func (e *engine) initialize(ctx context.Context, emit emitFunc) (_ any, err error) {
	defer func() {
		if err != nil {
			e.broken = true
		}
	}()
	e.lock = flock.New(filepath.Join(filepath.Dir(e.config.StorageState), ".native-signer.lock"))
	ok, err := e.lock.TryLock()
	if err != nil || !ok {
		return nil, failure("STATE_IN_USE", "Account directory cannot be exclusively locked.")
	}
	e.audit.configuration(ctx, e.config)
	e.session, err = loadSession(e.config.StorageState)
	if err != nil {
		return nil, err
	}
	e.audit.sessionState(ctx, "loaded", e.session)
	location, _ := e.readEgress(ctx) // Lookup failure keeps saved/fallback settings.
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	fp, err := loadAccountProfile(
		ctx, e.config.StorageState, e.config.Locale, e.config.Timezone, location,
	)
	if err != nil {
		return nil, err
	}
	e.fingerprint = fp
	e.shared.settingsMu.Lock()
	e.shared.fingerprint = fp
	e.shared.settingsMu.Unlock()
	e.egressTimezone = fp.Timezone
	e.profile, e.userAgent, e.language = profileFromConfig(fp.Config)
	if e.userAgent == "" || e.language == "" {
		return nil, failure("INVALID_STATE", "Runtime profile is missing its user agent or language.")
	}
	e.rhythm = *fp.Rhythm
	rt, err := transport.New(e.config.Proxy)
	if err != nil {
		return nil, err
	}
	var sender http.RoundTripper = rt
	if e.audit != nil {
		sender = &diagnosticTransport{next: rt, d: e.audit}
	}
	e.client = &http.Client{
		Transport: sender, // Cookie selection/merge is handled once, in do().
		Timeout:       0, // Generation is cancelled by the parent, not a client-wide timer.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	e.pageCache, err = loadPageCache(e.config.StorageState)
	if err != nil { return nil, err }
	if e.audit != nil {
		e.audit.record(ctx, "resource_cache_loaded", map[string]any{
			"loaded": e.pageCache.loaded, "entries": len(e.pageCache.entries),
		})
	}
	e.cacheDirectory = filepath.Join(filepath.Dir(e.config.StorageState), "interpreter-cache")
	if cacheErr := os.MkdirAll(e.cacheDirectory, 0700); cacheErr != nil {
		logLimited(ctx, logWarn, "interpreter_cache_unavailable", "解释器磁盘缓存不可用，将使用已校验的内存内容", map[string]any{"code": diagnosticError(cacheErr)})
	}
	return nil, e.openPage(ctx, emit)
}

// Shared account resources are prepared once by initialize(); every additional
// page executes exactly this page-local startup with its own context and VM.
func (e *engine) openPage(ctx context.Context, emit emitFunc) error {
	e.pointer = waa.NewPointer()
	e.lifetime, e.cancel = context.WithCancel(e.lifetime)
	if err := emit("progress", map[string]any{"stage": "loading_context", "pageId": e.pageID}); err != nil {
		return err
	}
	if err := e.loadPage(ctx); err != nil {
		return err
	}
	e.page = pageState{model: "models/" + e.config.Model}
	if err := emit("progress", map[string]any{"stage": "initializing_waa", "pageId": e.pageID}); err != nil {
		return err
	}
	if err := e.initializePageContext(ctx); err != nil {
		return err
	}
	saveCtx, cancelSave := context.WithTimeout(ctx, time.Second)
	_ = e.session.persist(saveCtx)
	cancelSave()
	if err := ctx.Err(); err != nil { return err }
	e.initialized = true
	e.audit.sessionState(ctx, "ready", e.session)
	// Start maintenance only after all startup tasks have joined. Its updates
	// cannot race the init result or the effective-profile diagnostic snapshot.
	e.vmMu.Lock()
	defer e.vmMu.Unlock()
	e.scheduleMaintenanceLocked()
	if e.audit != nil {
		interpreterHash := e.interpreterHash
		e.audit.record(ctx, "runtime_ready", map[string]any{
			"bootstrapModel": "models/" + e.config.Model,
			"effectiveLocale": e.profile.Locale, "effectiveTimezone": e.profile.TimeZone,
			"catalogModels": len(e.page.catalog), "interpreterHash": interpreterHash,
			"benefitStatus": e.tierStatus, "benefitTier": e.tier,
		})
	}
	return nil
}

func (e *engine) request(ctx context.Context, r *jsonRequest, emit emitFunc) (result any, err error) {
	if err := e.vmMu.LockContext(ctx); err != nil { return nil, err }
	defer e.vmMu.Unlock()
	requestStarted := time.Now()
	stage, upstreamStatus := "preparing", 0
	var bytesRead int64
	firstByteMs, eof, observation := int64(-1), false, "not_observed"
	if e.audit != nil {
		defer func() {
			cause := err
			if ctx.Err() != nil { cause = ctx.Err() }
			e.audit.record(ctx, "request_end", map[string]any{
				"stage": stage, "status": upstreamStatus, "eof": eof, "bytesRead": bytesRead,
				"firstByteMs": firstByteMs, "elapsedMs": time.Since(requestStarted).Milliseconds(),
				"localError": diagnosticError(cause), "observation": observation,
				"completionMeaning": "transport_only",
			})
		}()
	}
	if e.closed {
		return nil, failure("CLOSED", "Runtime is closed.")
	}
	if e.shared.broken.Load() {
		return nil, failure("RESTART_REQUIRED", "Account runtime cleanup is incomplete.")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	defer e.scheduleMaintenanceLocked()
	// A long stream may have delayed maintenance. Check at this idle boundary
	// before signing, without introducing a generation deadline.
	if err = e.refreshEgressLocked(ctx); err != nil {
		return nil, err
	}
	if e.shared.broken.Load() {
		return nil, failure("RESTART_REQUIRED", "Account runtime cleanup is incomplete.")
	}
	if e.refreshErr != nil || e.vm == nil || !time.Now().Before(e.vmExpires) {
		if err = emit("progress", map[string]any{"stage": "refreshing_waa"}); err != nil {
			return nil, err
		}
		refresh, cancel := context.WithTimeout(ctx, 120*time.Second)
		err = e.replaceVMLocked(refresh)
		cancel()
		if err != nil {
			e.broken = true
			return nil, failure("WAA_REFRESH_FAILED", "Runtime renewal failed.")
		}
	}
	if r.rerun && (!e.page.canRerun(r) || e.pointer.Clicked().IsZero()) {
		return nil, failure("INVALID_RERUN", "rerun requires the previous conversation and unchanged model/settings in this runtime.")
	}
	stage = "benefit"
	// This deadline belongs only to the auxiliary lookup. Generation continues
	// with the original cancellable context; no business request is replayed.
	benefitCtx, cancelBenefit := context.WithTimeout(ctx, benefitRefreshTimeout)
	e.subscription(benefitCtx)
	cancelBenefit()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = emit("progress", map[string]any{"stage": "signing"}); err != nil {
		return nil, err
	}
	if e.audit != nil {
		branch := "Generic"
		switch {
		case r.rerun: branch = "Rerun"
		case r.prompt != "": branch = "Run"
		case r.isFunctionResult: branch = "Submit"
		}
		e.audit.record(ctx, "sign_branch", map[string]any{
			"branch": branch, "explicitRerun": r.rerun,
			"sameContents": e.page.sameContents(r),
			"newChatPlanned": branch == "Run" && e.page.startsNewChat(r),
			"userRounds": r.userRounds(), "submitRounds": r.submitRounds(),
			"bootstrapModel": "models/" + e.config.Model, "requestModel": r.model,
			"pageAgeMs": time.Since(e.profile.NavigationStart).Milliseconds(),
			"interpreterHash": e.interpreterHash,
		})
	}
	stage = "signing"
	var timing prooftime.Timing
	signCtx, cancel := context.WithTimeout(ctx, time.Duration(e.config.SignTimeoutSeconds)*time.Second)
	signCtx = prooftime.With(signCtx, &timing)
	started := time.Now()
	var proof string
	running := r.rerun || r.prompt != "" || r.isFunctionResult
	switch {
	case r.rerun:
		proof, err = e.vm.RerunProof(signCtx, r.digest, max(r.userRounds(), 1))
	case r.prompt != "":
		var newChat func(time.Time)
		if e.page.startsNewChat(r) {
			newChat = func(time.Time) { e.page.previous = nil }
		}
		proof, err = e.vm.RunProofAfter(
			signCtx, r.digest, r.prompt, newChat, e.page.settingSteps(r), pickedPause,
		)
	case r.isFunctionResult:
		proof, err = e.vm.SubmitProof(signCtx, r.digest, r.functionResult, r.submitRounds())
	default:
		// Match the generic user-gesture proof path; do not pretend a media-only
		// or mixed function-result request was entered in a single text field.
		if err = e.vm.Activate(signCtx); err == nil {
			proof, err = e.vm.Proof(signCtx, r.digest, "")
		}
	}
	signCause := signCtx.Err()
	cancel()
	if err != nil || signCause != nil || len(proof) < 2 || !strings.HasPrefix(proof, "!") {
		e.broken = true
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(signCause, context.DeadlineExceeded) {
			return nil, failure("SIGN_TIMEOUT", "Native signing timed out.")
		}
		return nil, failure("SIGN_FAILED", "Native signing failed.")
	}
	proofMs := time.Since(started).Milliseconds()
	if e.audit != nil {
		e.audit.record(ctx, "signed", map[string]any{
			"proofPresent": proof != "", "proofChars": len(proof), "proofMs": proofMs,
			"interactionMs": timing.Duration(prooftime.Interaction).Milliseconds(),
			"computeMs": timing.Duration(prooftime.Compute).Milliseconds(),
			"lockMs": timing.Duration(prooftime.Lock).Milliseconds(), "skippedSteps": timing.Skipped(),
		})
	}
	stage = "metrics"
	// Drain metrics locally. This component does not send the reference telemetry.
	metricsCtx, stopMetrics := context.WithTimeout(ctx, time.Second)
	_, metricsErr := e.vm.TakeMetrics(metricsCtx)
	stopMetrics()
	if ctx.Err() != nil { return nil, ctx.Err() }
	if metricsErr != nil {
		if errors.Is(metricsErr, context.DeadlineExceeded) {
			// A delayed housekeeping task is not evidence that the fresh proof
			// or VM is unusable. The queued task can still drain metrics later.
			logEvent(ctx, logDebug, "metrics_deferred", "运行指标清理延后，不影响本次签名", map[string]any{"pageId": e.pageID})
		} else {
			e.broken = true
			return nil, failure("RUNTIME_UNRESPONSIVE", "Native event loop is unavailable.")
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	stage = "authentication"
	headers, err := e.rpcHeaders(e.apiKey)
	if err != nil {
		return nil, err
	}
	if e.tier == "TIER1" || e.tier == "TIER2" {
		headers.Set("X-AIStudio-G1-Tier", e.tier)
	}
	if err = emit("progress", map[string]any{"stage": "sending_upstream"}); err != nil {
		return nil, err
	}
	headers.Set("Priority", "u=0")
	finishCount := e.startCountTokens(ctx, r, headers)
	completed := false
	defer func() { finishCount(completed) }()
	if running {
		e.page.remember(r)
	}
	stage = "sending"
	sent := time.Now()
	response, err := e.do(ctx, http.MethodPost, generateURL, r.signedBody(proof), headers)
	if err != nil {
		e.page.previous = nil
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var local *ipcError
		if errors.As(err, &local) {
			// do() may detect expired credentials after rpcHeaders() succeeded.
			// Preserve that account fact without exposing raw transport errors.
			return nil, local
		}
		return nil, failure("FETCH_FAILED", "Google request failed before response headers.")
	}
	upstreamStatus = response.StatusCode
	stage = "reading"
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = response.Body.Close()
		}
		if running && !e.vm.NotifyReplaced() {
			e.broken = true
		}
		if err != nil || response.StatusCode != http.StatusOK {
			e.page.previous = nil
		}
		// Disk maintenance must not change an already-completed Google result
		// or cancel other leases. One account-owned save is reused by all pages.
		saveCtx, stopSave := context.WithTimeout(ctx, time.Second)
		persistence := e.session.persist(saveCtx)
		stopSave()
		if end, ok := result.(map[string]any); ok { end["persistence"] = persistence }
	}()
	if response.StatusCode != http.StatusOK {
		e.page.previous = nil
	}
	if running && !e.vm.NotifyReplaced() {
		e.broken = true
	}
	var observed *responseObserver
	if running && response.StatusCode == http.StatusOK {
		observed = newResponseObserver(e.vm, r.rerun)
	}
	if err = emit("headers", map[string]any{
		"status": response.StatusCode,
		"headers": outputHeaders(response.Header),
		"timing": map[string]any{
			"proofMs": proofMs, "headersMs": time.Since(sent).Milliseconds(),
			"lockMs": timing.Duration(prooftime.Lock).Milliseconds(),
			"interactionMs": timing.Duration(prooftime.Interaction).Milliseconds(),
			"computeMs": timing.Duration(prooftime.Compute).Milliseconds(),
			"skippedSteps": timing.Skipped(),
		},
	}); err != nil {
		return nil, err
	}
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			bytesRead += int64(n)
			if firstByteMs < 0 { firstByteMs = time.Since(requestStarted).Milliseconds() }
			if err = emit("chunk", map[string]any{
				"base64": base64.StdEncoding.EncodeToString(buffer[:n]),
			}); err != nil {
				return nil, err
			}
			if observed != nil {
				observed.feed(buffer[:n])
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return nil, failure("READ_FAILED", "Google response stream ended abnormally.")
			}
			eof = true
			break
		}
	}
	err = response.Body.Close()
	bodyClosed = true
	if err != nil {
		return nil, failure("READ_FAILED", "Failed to close the upstream response.")
	}
	if observed != nil {
		observation = "complete"
		if !observed.complete() {
			observation = "incomplete"
			e.page.previous = nil
			logLimited(ctx, logWarn, "response_observation_incomplete", "响应阶段观察不完整，原始正文仍保持透传", map[string]any{"pageId": e.pageID})
		}
	}
	stage = "finished"
	completed = true
	return map[string]any{"status": response.StatusCode}, nil
}

func outputHeaders(source http.Header) http.Header {
	h := source.Clone()
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length",
		"Content-Encoding", "Set-Cookie", "Set-Cookie2",
	} {
		h.Del(name)
	}
	return h
}

func (e *engine) closePage() error {
	e.closeOnce.Do(func() {
		if e.cancel != nil { e.cancel() }
		e.vmMu.Lock()
		defer e.vmMu.Unlock()
		e.closed = true
		e.refreshSequence++
		if e.refreshTimer != nil {
			e.refreshTimer.Stop()
			e.refreshTimer = nil
		}
		e.background.Wait()
		if e.vm != nil {
			e.closeErr = errors.Join(e.closeErr, e.vm.Close())
			if e.closeErr == nil {
				e.vm = nil
			} else {
				e.shared.retire()
			}
		}
	})
	return e.closeErr
}

// Shared account resources close only after all pages and operations stop.
func (e *engine) closeAccount() error {
	var err error
	if e.client != nil {
		if closer, ok := e.client.Transport.(io.Closer); ok {
			err = closer.Close()
		} else {
			e.client.CloseIdleConnections()
		}
	}
	if e.session != nil {
		e.session.waitPersistence()
		err = errors.Join(err, e.session.save())
	}
	if e.lock != nil {
		err = errors.Join(err, e.lock.Close())
		e.lock = nil
	}
	return err
}
