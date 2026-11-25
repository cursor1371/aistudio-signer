package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// pageMutex permits cancelling a lease while maintenance owns the page.
// Ordinary Lock is used only by lifecycle code, never a business waiter.
type pageMutex struct {
	once sync.Once
	gate chan struct{}
}
func (m *pageMutex) LockContext(ctx context.Context) error {
	m.once.Do(func() { m.gate = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil { return err }
	select {
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil { <-m.gate; return err }
		return nil
	case <-ctx.Done(): return ctx.Err()
	}
}
func (m *pageMutex) Lock() { _ = m.LockContext(context.Background()) }
func (m *pageMutex) Unlock() { <-m.gate }

// Account-scoped state only; navigation, conversation, pointer and VM remain
// page-local. Cookie, storage and resource cache provide their own locks.
type accountRuntime struct {
	lifetime context.Context
	cancel context.CancelFunc
	broken atomic.Bool
	failed chan struct{}
	settingsMu sync.Mutex
	fingerprint *accountProfile
	egressGate chan struct{}
	interpreterGate chan struct{}
	checked time.Time
	location egressLocation
	egressErr error

	benefitMu sync.Mutex
	benefit benefitState
	benefitFlight *benefitFlight
}

type benefitState struct {
	tier, status string
	confirmedAt  time.Time // changes only after a successful lookup
	expires      time.Time // refresh due time, not the stale fallback deadline
}

func (s benefitState) fresh(now time.Time) bool {
	return s.status == "resolved" && !s.confirmedAt.IsZero() && now.Before(s.expires)
}

func (s benefitState) usable(now time.Time) bool {
	return (s.status == "resolved" || s.status == "stale") &&
		!s.confirmedAt.IsZero() && now.Before(s.confirmedAt.Add(benefitMaxAge))
}

func (s benefitState) ageMs(now time.Time) int64 {
	if s.confirmedAt.IsZero() {
		return -1
	}
	return max(now.Sub(s.confirmedAt).Milliseconds(), 0)
}

type benefitFlight struct {
	done       chan struct{}
	allowStale bool // published before done closes; does not extend cache age
}

func newAccountRuntime(parent context.Context) *accountRuntime {
	ctx, cancel := context.WithCancel(parent)
	return &accountRuntime{
		lifetime: ctx, cancel: cancel, failed: make(chan struct{}),
		egressGate: make(chan struct{}, 1),
		interpreterGate: make(chan struct{}, 1),
	}
}

func (a *accountRuntime) retire() {
	if a.broken.CompareAndSwap(false, true) {
		close(a.failed)
	}
}

func (a *accountRuntime) close() {
	a.benefitMu.Lock()
	a.cancel()
	flight := a.benefitFlight
	a.benefitMu.Unlock()
	if flight != nil {
		<-flight.done // finishes before the shared HTTP client/session is closed
	}
}

func (a *accountRuntime) profileSnapshot() (*accountProfile, error) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	// A deep copy prevents nested JS profile arrays/maps from crossing pages.
	data, err := json.Marshal(a.fingerprint)
	if err != nil { return nil, err }
	var result accountProfile
	if err = json.Unmarshal(data, &result); err != nil { return nil, err }
	if result.Rhythm == nil || len(result.Config) == 0 {
		return nil, failure("INVALID_STATE", "Account runtime settings are unavailable.")
	}
	return &result, nil
}

// Snapshot is nonblocking with respect to network requests and page leases.
func (a *accountRuntime) benefitSnapshot() benefitState {
	a.benefitMu.Lock()
	defer a.benefitMu.Unlock()
	return a.benefit
}

func (a *accountRuntime) invalidateBenefit() {
	a.benefitMu.Lock()
	a.benefit = benefitState{status: "unavailable"}
	a.benefitMu.Unlock()
}

// A lookup belongs to the account, not to the request that first needed it.
// Each caller cancels only its wait. There is one bounded lookup, no retry loop.
func (e *engine) subscription(ctx context.Context) {
	e.tier, e.tierStatus, e.tierExpires = "", "unavailable", time.Time{}
	if ctx.Err() != nil {
		return
	}
	a := e.shared
	a.benefitMu.Lock()
	if a.lifetime.Err() != nil {
		a.benefitMu.Unlock()
		return
	}
	cached, now := a.benefit, time.Now()
	if cached.fresh(now) {
		a.benefitMu.Unlock()
		e.applySubscription(ctx, cached, cached, now, "cache")
		return
	}
	flight := a.benefitFlight
	if flight == nil {
		flight = &benefitFlight{done: make(chan struct{})}
		a.benefitFlight = flight
		budget := benefitRefreshTimeout
		if !e.initialized {
			budget = time.Duration(e.config.InitTimeoutSeconds) * time.Second
		}
		if deadline, ok := ctx.Deadline(); ok {
			budget = min(budget, max(time.Until(deadline), 0))
		}
		// Copy only immutable HTTP inputs. The originating page may finish,
		// renew or close while another page still waits for this lookup.
		lookup := &engine{
			shared: a, session: e.session, client: e.client, audit: e.audit,
			config: e.config, pageID: e.pageID, apiKey: e.apiKey,
			userAgent: e.userAgent, language: e.language, visitID: e.visitID,
			initialized: e.initialized,
		}
		if e.initialized {
			lookup.logHeader = e.logHeader
		}
		queryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
		stopAccount := context.AfterFunc(a.lifetime, cancel)
		go func() {
			defer cancel()
			defer stopAccount()
			result, transient := lookup.lookupSubscription(queryCtx)
			a.benefitMu.Lock()
			previous := a.benefit
			published := a.lifetime.Err() == nil
			if published {
				switch {
				case result.status == "resolved":
					a.benefit = result
				case transient:
					if !a.benefit.confirmedAt.IsZero() {
						a.benefit.status = "stale"
					}
				default:
					a.benefit = benefitState{status: "unavailable"}
				}
			}
			flight.allowStale = transient
			a.benefitFlight = nil
			close(flight.done)
			a.benefitMu.Unlock()
			if published && result.status == "resolved" && (previous.status != "resolved" || previous.tier != result.tier) {
				logEvent(queryCtx, logInfo, "benefit_resolved", "账号权益已确认或恢复", map[string]any{"tier": result.tier, "subscriptionHeaderAvailable": result.tier != ""})
			}
		}()
	}
	a.benefitMu.Unlock()
	select {
	case <-flight.done:
		e.selectSubscription(ctx, flight.allowStale, "shared_lookup")
	case <-ctx.Done():
		e.selectSubscription(ctx, errors.Is(ctx.Err(), context.DeadlineExceeded), "wait_timeout")
	}
}

// Read the latest account state, not a pre-wait copy: a new successful lookup
// or invalidation must never be overwritten by an older page's fallback.
func (e *engine) selectSubscription(ctx context.Context, allowStale bool, source string) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	cached := e.shared.benefitSnapshot()
	now := time.Now()
	selected := benefitState{status: "unavailable"}
	switch {
	case cached.fresh(now):
		selected = cached
	case allowStale && cached.usable(now):
		selected = cached
		selected.status = "stale"
	}
	e.applySubscription(ctx, cached, selected, now, source)
}

func (e *engine) applySubscription(ctx context.Context, cached, selected benefitState, now time.Time, source string) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	e.tier, e.tierStatus, e.tierExpires = selected.tier, selected.status, selected.expires
	if selected.status != "resolved" {
		logLimited(ctx, logWarn, "benefit_degraded", "权益状态降级，本次请求按既有缓存策略继续", map[string]any{"pageId": e.pageID, "state": selected.status, "tier": selected.tier, "cacheAgeMs": cached.ageMs(now)})
	}
	e.audit.record(ctx, "benefit_selection", map[string]any{
		"pageId": e.pageID, "source": source,
		"status": selected.status, "selectedTier": selected.tier,
		"staleUsed": selected.status == "stale", "cacheAgeMs": cached.ageMs(now),
		"cacheRemainingMs": max(cached.expires.Sub(now).Milliseconds(), 0),
		"staleRemainingMs": max(cached.confirmedAt.Add(benefitMaxAge).Sub(now).Milliseconds(), 0),
	})
}

type pageSlot struct {
	id int
	page *engine
	ready bool // pool-owned, published only after page initialization
	leased bool // includes creation and retirement; never freed before cleanup
}

// executor is a bounded account-local lease pool, not a business scheduler.
// The IPC dispatcher caps admitted requests; there is no waiting business queue.
type executor struct {
	config config
	lifetime context.Context
	audit *diagnostics
	shared *accountRuntime
	root *engine // owns account lock, HTTP client and shared cache
	mu sync.Mutex
	pages []*pageSlot
	nextPage int
	opening chan struct{}
	attempted, initialized, closed bool
	validation *sessionValidationResult // last completed observation, not an admission decision
	broken *atomic.Bool // aliases the account-wide failure flag
}

func newExecutor(cfg config, ctx context.Context, audit *diagnostics) *executor {
	shared := newAccountRuntime(ctx)
	return &executor{config: cfg, lifetime: shared.lifetime, audit: audit,
		shared: shared, broken: &shared.broken, opening: make(chan struct{}, 1)}
}

func (x *executor) status() map[string]any {
	x.mu.Lock()
	phase := "not_initialized"
	if x.attempted { phase = "initializing" }
	if x.initialized { phase = "ready" }
	if x.broken.Load() || x.closed { phase = "restart_required" }
	ready, leased := 0, 0
	for _, slot := range x.pages {
		if slot.ready { ready++ }
		if slot.leased { leased++ }
	}
	count := len(x.pages)
	validation := x.validation
	var session *accountSession
	if x.initialized && x.root != nil { session = x.root.session }
	x.mu.Unlock()
	var persistence any
	if session != nil { persistence = session.persistenceStatus() }
	benefit := x.shared.benefitSnapshot()
	now := time.Now()
	fresh, usable := benefit.fresh(now), benefit.usable(now)
	status, tier := benefit.status, benefit.tier
	if !usable {
		status, tier = "unavailable", ""
	}
	return map[string]any{
		"phase": phase, "capacity": x.config.Capacity,
		"pages": count, "readyPages": ready, "leasedPages": leased,
		"sessionValidation": validation, "persistence": persistence,
		"benefitStatus": status, "benefitTier": tier,
		"benefitCacheFresh": fresh, "benefitCacheUsable": usable,
		"benefitCacheAgeMs": benefit.ageMs(now),
	}
}

func (x *executor) execute(ctx context.Context, cmd command, emit emitFunc) (result any, err error) {
	ctx = x.audit.begin(ctx, cmd)
	started := time.Now()
	defer func() {
		if x.audit == nil { return }
		op := ctx.Value(diagnosticOperationKey{}).(*diagnosticOperation)
		cause := err
		if ctx.Err() != nil { cause = ctx.Err() }
		x.audit.record(ctx, "operation_end", map[string]any{
			"elapsedMs": time.Since(started).Milliseconds(), "localError": diagnosticError(cause),
			"generateHandoffs": op.generate.Load(), "restartRequired": x.broken.Load(),
			"resourcesCumulative": x.audit.resourcesSnapshot(),
		})
	}()
	if x.broken.Load() { return nil, failure("RESTART_REQUIRED", "Account runtime must be restarted.") }
	if cmd.Op == "validate_session" {
		return x.validateSession(ctx, cmd.Params)
	}
	if cmd.Op == "init" {
		x.mu.Lock()
		if x.attempted { x.mu.Unlock(); return nil, failure("ALREADY_INITIALIZED", "Initialization is allowed once per process.") }
		x.attempted = true
		x.root = &engine{config: x.config, lifetime: x.lifetime, audit: x.audit, shared: x.shared, pageID: 1}
		root := x.root
		x.mu.Unlock()
		_, err = root.initialize(ctx, emit)
		if err != nil { x.shared.retire(); return nil, err }
		x.mu.Lock()
		x.pages = []*pageSlot{{id: 1, page: root, ready: true}}
		x.nextPage, x.initialized = 1, true
		x.mu.Unlock()
		result := x.status()
		result["elapsedMs"] = time.Since(started).Milliseconds()
		return result, nil
	}
	var params requestParams
	if err = decode(cmd.Params, &params); err != nil { return nil, err }
	r, err := parseRequest(params)
	if err != nil { return nil, err }
	if x.audit != nil { x.audit.record(ctx, "request_input", diagnosticRequest(r)) }
	slot, err := x.acquire(ctx, r, emit)
	if err != nil { return nil, err }
	x.audit.record(ctx, "page_lease", map[string]any{"pageId": slot.id, "state": "acquired", "capacity": x.config.Capacity})
	defer func() {
		state := "released"
		if !x.release(slot) {
			state = "cleanup_failed"
			x.shared.retire()
			if err == nil { err = failure("RESTART_REQUIRED", "Page cleanup did not complete.") }
		}
		x.audit.record(ctx, "page_lease", map[string]any{"pageId": slot.id, "state": state})
	}()
	result, err = slot.page.request(ctx, r, emit)
	return result, err
}

func (x *executor) acquire(ctx context.Context, r *jsonRequest, emit emitFunc) (*pageSlot, error) {
	x.mu.Lock()
	if !x.initialized || x.closed || x.broken.Load() {
		x.mu.Unlock()
		return nil, failure("NOT_INITIALIZED", "Account runtime is not ready.")
	}
	var free *pageSlot
	for _, slot := range x.pages {
		if slot.leased || !slot.ready { continue }
		if free == nil { free = slot }
		// An idle page's conversation cannot change until it is leased.
		if slot.page.page.canRerun(r) { free = slot; break }
	}
	if r.rerun && (free == nil || !free.page.page.canRerun(r)) {
		x.mu.Unlock()
		return nil, failure("INVALID_RERUN", "No idle page owns the requested previous conversation.")
	}
	if free != nil {
		free.leased = true
		x.mu.Unlock()
		return free, nil
	}
	if len(x.pages) >= x.config.Capacity {
		x.mu.Unlock()
		return nil, failure("BUSY", "Account execution capacity is occupied; no internal request queue.")
	}
	x.nextPage++
	slot := &pageSlot{id: x.nextPage, leased: true}
	x.pages = append(x.pages, slot) // reserve capacity before waiting for creation
	x.mu.Unlock()

	select {
	case x.opening <- struct{}{}:
	case <-ctx.Done():
		x.remove(slot)
		return nil, ctx.Err()
	}
	defer func() { <-x.opening }()
	if err := ctx.Err(); err != nil { x.remove(slot); return nil, err }

	// A prior request may have released a page while this request waited for
	// the creation gate. Reuse it rather than consuming another native VM.
	x.mu.Lock()
	if x.closed || x.broken.Load() {
		x.removeLocked(slot)
		x.mu.Unlock()
		return nil, failure("RESTART_REQUIRED", "Account runtime is closing.")
	}
	free = nil
	for _, candidate := range x.pages {
		if candidate.leased || !candidate.ready { continue }
		if free == nil { free = candidate }
		if candidate.page.page.canRerun(r) { free = candidate; break }
	}
	if free != nil {
		free.leased = true
		x.removeLocked(slot)
		x.mu.Unlock()
		return free, nil
	}
	x.mu.Unlock()

	// The page startup budget starts only when actual creation can begin.
	initCtx, cancel := context.WithTimeout(ctx, time.Duration(x.config.InitTimeoutSeconds)*time.Second)
	defer cancel()
	fp, err := x.shared.profileSnapshot()
	if err != nil { x.remove(slot); return nil, err }
	page := &engine{
		config: x.config, lifetime: x.lifetime, audit: x.audit, shared: x.shared, pageID: slot.id,
		client: x.root.client, session: x.root.session, pageCache: x.root.pageCache,
		cacheDirectory: x.root.cacheDirectory, fingerprint: fp, rhythm: *fp.Rhythm,
		egressTimezone: fp.Timezone,
	}
	page.profile, page.userAgent, page.language = profileFromConfig(fp.Config)
	x.mu.Lock()
	slot.page = page // closing must see partial startup as well as ready pages
	x.mu.Unlock()
	logEvent(ctx, logInfo, "page_creating", "正在按需创建执行页面", map[string]any{"pageId": slot.id, "capacity": x.config.Capacity})
	createdAt := time.Now()
	if err = emit("progress", map[string]any{"stage": "creating_page", "pageId": slot.id}); err == nil {
		err = page.openPage(initCtx, emit)
	}
	if err != nil {
		if stopPageBounded(page) { x.remove(slot) } else { x.shared.retire() }
		return nil, err
	}
	x.mu.Lock()
	slot.ready = true
	x.mu.Unlock()
	logEvent(ctx, logInfo, "page_ready", "执行页面已就绪", map[string]any{"pageId": slot.id, "elapsedMs": time.Since(createdAt).Milliseconds()})
	return slot, nil
}

func (x *executor) remove(slot *pageSlot) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(slot)
}

func (x *executor) removeLocked(slot *pageSlot) {
	for i, candidate := range x.pages {
		if candidate == slot {
			copy(x.pages[i:], x.pages[i+1:])
			x.pages[len(x.pages)-1] = nil
			x.pages = x.pages[:len(x.pages)-1]
			return
		}
	}
}

func stopPageBounded(page *engine) bool {
	done := make(chan error, 1)
	go func() { done <- page.closePage() }()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(shutdownGrace):
		return false // do not reuse or replace an unconfirmed live native context
	}
}

func (x *executor) release(slot *pageSlot) bool {
	if slot.page.broken {
		x.mu.Lock()
		slot.ready = false
		x.mu.Unlock()
		if !stopPageBounded(slot.page) { return false }
		x.remove(slot)
		logEvent(nil, logWarn, "page_retired", "故障页面已回收，其余页面继续服务", map[string]any{"pageId": slot.id})
		return true
	}
	x.mu.Lock()
	slot.leased = false
	x.mu.Unlock()
	return true
}

// Called only after admitted operations have returned. Cancel all pages first,
// then close in parallel so one slow VM does not postpone cancellation of peers.
func (x *executor) close() error {
	x.mu.Lock()
	x.closed = true
	pages := append([]*pageSlot(nil), x.pages...)
	root := x.root
	x.mu.Unlock()
	x.shared.close()
	var group sync.WaitGroup
	var closeMu sync.Mutex
	var closeErr error
	seen := map[*engine]bool{}
	for _, slot := range pages {
		if slot.page != nil { seen[slot.page] = true }
	}
	if root != nil { seen[root] = true }
	for page := range seen { if page.cancel != nil { page.cancel() } }
	for page := range seen {
		group.Add(1)
		go func() {
			defer group.Done()
			err := page.closePage()
			closeMu.Lock()
			closeErr = errors.Join(closeErr, err)
			closeMu.Unlock()
		}()
	}
	group.Wait()
	if closeErr != nil {
		// Keep the account lock and shared state alive until process exit if
		// any native context still owns callbacks into these resources.
		return closeErr
	}
	if root != nil { return root.closeAccount() }
	return nil
}
