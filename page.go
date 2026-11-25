package main

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"local/aistudio-signer/waa"
)

// Durations and transition rules follow runtime_settings.go in v0.3.13.
const (
	selectorPause = 2900 * time.Millisecond
	pickedPause   = 3900 * time.Millisecond
	levelPause    = 1900 * time.Millisecond
	systemPause   = 2900 * time.Millisecond
	closePause    = 1450 * time.Millisecond
	togglePause   = 1900 * time.Millisecond
	dialogPause   = 5900 * time.Millisecond
)

type pageModel struct {
	level    int64
	featured bool
}

type pageState struct {
	model                   string
	level                   int64
	system, tools           string
	groundingOff, functions bool
	catalog                 map[string]pageModel
	previous                []string
	previousSettings        string
}

func (p *pageState) sameContents(r *jsonRequest) bool {
	if p.previous == nil || len(p.previous) != len(r.contents) {
		return false
	}
	for i, value := range p.previous {
		if r.contentKeys()[i] != value {
			return false
		}
	}
	return true
}

// Same history is not a new chat. Only exactly two appended turns with the
// intervening model turn continue an existing chat. JSON key order is ignored.
func (p *pageState) startsNewChat(r *jsonRequest) bool {
	if p.previous == nil || p.sameContents(r) {
		return false
	}
	if len(r.contents) != len(p.previous)+2 || r.roles[len(p.previous)] != "model" {
		return true
	}
	for i, value := range p.previous {
		if r.contentKeys()[i] != value {
			return true
		}
	}
	return false
}

func (p *pageState) canRerun(r *jsonRequest) bool {
	return p.sameContents(r) && p.previousSettings == r.settingsKey()
}

func (p *pageState) remember(r *jsonRequest) {
	p.previousSettings = r.settingsKey()
	p.previous = make([]string, len(r.contents))
	copy(p.previous, r.contentKeys())
}

func (p *pageState) pageLevel(model string) int64 {
	if model != p.model {
		if entry, ok := p.catalog[model]; ok {
			return entry.level
		}
	}
	return p.level
}

// thinkingLevel is a local settings view, not a request enum converter.
// GenerateContent's numeric 6 corresponds to catalogue level 5 (Extra High).
func thinkingLevel(raw json.RawMessage) int64 {
	var value int64
	if json.Unmarshal(raw, &value) == nil {
		if value == 6 {
			return 5
		}
		return value
	}
	switch strings.ToLower(textValue(raw)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "minimal":
		return 4
	case "extra_high":
		return 5
	default:
		return 0
	}
}

// Only callbacks for completed VM actions commit settings. Skipped groups do
// not change local state. Business fields are neither normalized nor replaced.
func (p *pageState) settingSteps(r *jsonRequest) [][]waa.SettingStep {
	var groups [][]waa.SettingStep
	wait := func() time.Duration {
		if len(groups) == 0 {
			return 0
		}
		return pickedPause
	}
	if model, listed := p.catalog[r.model]; listed && r.model != p.model {
		group := []waa.SettingStep{{Wait: wait(), To: "selector"}}
		if !model.featured {
			group = append(group, waa.SettingStep{Wait: selectorPause, To: "all"})
		}
		groups = append(groups, append(group, waa.SettingStep{
			Wait: selectorPause, To: "row", Clicked: func(time.Time) {
				p.model, p.level = r.model, model.level
			},
		}))
	}
	var gc, tc map[string]json.RawMessage
	_ = json.Unmarshal(alias(r.fields, "generationConfig", "generation_config"), &gc)
	_ = json.Unmarshal(alias(gc, "thinkingConfig", "thinking_config"), &tc)
	if level := thinkingLevel(alias(tc, "thinkingLevel", "thinking_level")); level != 0 && level != p.pageLevel(r.model) {
		groups = append(groups, []waa.SettingStep{
			{Wait: wait(), To: "level"},
			{Wait: levelPause, To: "option", Clicked: func(time.Time) { p.level = level }},
		})
	}
	system := alias(r.fields, "systemInstruction", "system_instruction")
	if key, text := canonical(system), contentText(system); key != p.system && text != "" {
		groups = append(groups, []waa.SettingStep{
			{Wait: wait(), To: "system"},
			{Wait: systemPause, To: "instructions", Text: text},
			{Wait: closePause, To: "close", Clicked: func(time.Time) { p.system = key }},
		})
	}

	// In JSON, field names themselves contain quotes. The reference's quote
	// heuristic for wire tools must therefore become a declaration check.
	var tools []map[string]json.RawMessage
	_ = json.Unmarshal(r.fields["tools"], &tools)
	hasDeclarations := false
	for _, tool := range tools {
		var declarations []json.RawMessage
		if json.Unmarshal(alias(tool, "functionDeclarations", "function_declarations"), &declarations) == nil && len(declarations) != 0 {
			hasDeclarations = true
		}
	}
	if toolsKey := canonical(r.fields["tools"]); hasDeclarations && toolsKey != p.tools {
		var group []waa.SettingStep
		pause := wait()
		if !p.groundingOff {
			group = append(group, waa.SettingStep{
				Wait: pause, To: "grounding", Clicked: func(time.Time) { p.groundingOff = true },
			})
			pause = togglePause
		}
		if !p.functions {
			group = append(group, waa.SettingStep{
				Wait: pause, To: "functions", Clicked: func(time.Time) { p.functions = true },
			})
			pause = togglePause
		}
		groups = append(groups, append(group,
			waa.SettingStep{Wait: pause, To: "edit"},
			waa.SettingStep{Wait: dialogPause, To: "declarations", Text: toolsKey},
			waa.SettingStep{Wait: closePause, To: "save", Clicked: func(time.Time) { p.tools = toolsKey }},
		))
	}
	return groups
}

// ListModels is an internal catalogue RPC, not a conversion of business input.
// Only the fields used by page_settings.go are read: name, default level and
// Featured membership. The numeric positions come from parseCatalogModels.
func (e *engine) loadModelCatalog(ctx context.Context) error {
	headers, err := e.rpcHeaders(e.apiKey)
	if err != nil {
		return err
	}
	response, err := e.do(ctx, http.MethodPost, makerRPC+"ListModels", []byte("[]"), headers)
	if err != nil {
		return err
	}
	body, err := readBounded(response, bootstrapLimit)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return failure("CATALOG_HTTP", "Cannot load the model settings catalogue.")
	}
	var root []json.RawMessage
	var rows [][]json.RawMessage
	if json.Unmarshal(fillSparseArraySlots(body), &root) != nil || len(root) == 0 ||
		json.Unmarshal(root[0], &rows) != nil || rows == nil {
		return failure("CATALOG_FORMAT", "Unsupported model catalogue format.")
	}
	catalog := make(map[string]pageModel, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		name := textValue(row[0])
		if name == "" {
			continue
		}
		var model pageModel
		var thinking []json.RawMessage
		if len(row) > 71 && json.Unmarshal(row[71], &thinking) == nil && len(thinking) > 5 {
			_ = json.Unmarshal(thinking[5], &model.level)
		}
		var categories []int64
		if len(row) > 74 && json.Unmarshal(row[74], &categories) == nil {
			for _, category := range categories {
				model.featured = model.featured || category == 10
			}
		}
		catalog[name] = model
	}
	e.page.catalog = catalog
	e.page.level = catalog[e.page.model].level
	return nil
}

// The auxiliary JSPB catalogue can omit array elements. This normalization is
// never applied to GenerateContent requests or their raw JSON response stream.
func fillSparseArraySlots(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	var previous byte
	inString, escaped := false, false
	for _, c := range raw {
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == ',' && (previous == '[' || previous == ',') || c == ']' && previous == ',' {
			out = append(out, "null"...)
		}
		out = append(out, c)
		if c == '"' {
			inString = true
		}
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			previous = c
		}
	}
	return out
}

// startCountTokens schedules one companion request, not a second generation.
// A normally completed stream does not cancel its pending companion. Explicit
// cancellation, transport failure and component shutdown do cancel it.
func (e *engine) startCountTokens(parent context.Context, r *jsonRequest, headers http.Header) func(bool) {
	var contents any
	var delay time.Duration
	switch {
	case r.rerun:
		return func(bool) {}
	case r.prompt != "":
		contents = []any{map[string]any{
			"role": "user", "parts": []any{map[string]string{"text": r.prompt}},
		}}
		delay = 2200 * time.Millisecond
	case r.isFunctionResult && len(r.contents) >= 2:
		contents = r.contents[len(r.contents)-2:]
		delay = 250*time.Millisecond + rand.N(150*time.Millisecond)
	default:
		return func(bool) {}
	}
	body, err := json.Marshal(map[string]any{"model": r.model, "contents": contents})
	if err != nil {
		return func(bool) {}
	}
	companion := headers.Clone()
	companion.Del("Priority")
	ctx, cancel := context.WithTimeout(e.lifetime, 30*time.Second)
	stopParent := context.AfterFunc(parent, cancel)
	at := time.Now().Add(delay)
	e.background.Add(1)
	go func() {
		defer e.background.Done()
		defer cancel()
		defer stopParent()
		if waitUntil(ctx, at) != nil {
			return
		}
		response, err := e.do(ctx, http.MethodPost, makerRPC+"CountTokens"+jsonQuery, body, companion)
		if err != nil {
			if ctx.Err() == nil {
				logEvent(parent, logDebug, "count_tokens_failed", "伴随 Token 查询连接失败", map[string]any{"pageId": e.pageID, "code": diagnosticError(err)})
			}
			return
		}
		_, readErr := readBounded(response, 1<<20)
		if (readErr != nil || response.StatusCode != http.StatusOK) && ctx.Err() == nil {
			logEvent(parent, logDebug, "count_tokens_failed", "伴随 Token 查询未成功完成", map[string]any{"pageId": e.pageID, "status": response.StatusCode, "code": diagnosticError(readErr)})
		}
		_ = e.session.persist(ctx) // failure is reported as account health, not model failure
	}()
	return func(completed bool) {
		stopParent()
		if !completed {
			cancel()
		}
	}
}
