package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	logDebug = slog.LevelDebug
	logInfo  = slog.LevelInfo
	logWarn  = slog.LevelWarn
	logError = slog.LevelError

	logQueueSize = 128
	logReserve   = 16
	maxLogBytes  = 64 << 10
)

// Each executable owns its logger. All records are encoded before enqueueing;
// the writer never retains a caller's mutable fields or blocks protocol work.
type logOutput struct {
	mu        sync.Mutex
	closed    bool
	level     slog.Level
	format    string
	component string
	pid       int
	queue     chan []byte
	done      chan struct{}
	failed    atomic.Bool
	dropped   atomic.Uint64
	notices   map[string]logNotice // static maintenance event names only
}

type logNotice struct {
	at         time.Time
	level      slog.Level
	suppressed uint64
}

func newLogOutput(writer io.Writer, component string) *logOutput {
	out := &logOutput{
		level: logInfo, format: "text", component: component, pid: os.Getpid(),
		queue: make(chan []byte, logQueueSize), done: make(chan struct{}),
		notices: make(map[string]logNotice),
	}
	go func() {
		defer close(out.done)
		write := func(data []byte) bool {
			n, err := writer.Write(data)
			if err != nil || n != len(data) {
				out.failed.Store(true)
				return false
			}
			return true
		}
		var reported uint64
		var reportedAt time.Time
		reportDropped := func(force bool) bool {
			total := out.dropped.Load()
			if total == reported || !force && time.Since(reportedAt) < time.Minute {
				return true
			}
			out.mu.Lock()
			level := max(logWarn, out.level)
			out.mu.Unlock()
			data := out.encode(level, "logs_dropped", "日志输出积压，部分记录已丢弃", map[string]any{
				"count": total - reported, "total": total,
			})
			if len(data) == 0 || !write(data) {
				return false
			}
			reported, reportedAt = total, time.Now()
			return true
		}
		reportSuppressed := func() bool {
			out.mu.Lock()
			snapshot := make(map[string]logNotice, len(out.notices))
			for event, notice := range out.notices {
				if notice.suppressed != 0 {
					snapshot[event] = notice
				}
			}
			threshold := out.level
			out.mu.Unlock()
			for event, notice := range snapshot {
				data := out.encode(max(notice.level, threshold), "logs_suppressed", "重复维护日志已合并", map[string]any{
					"sourceEvent": event, "suppressed": notice.suppressed,
				})
				if len(data) == 0 || !write(data) {
					return false
				}
				out.mu.Lock()
				current := out.notices[event]
				current.suppressed -= notice.suppressed
				out.notices[event] = current
				out.mu.Unlock()
			}
			return true
		}
		// The existing writer also reports quiet tails; no per-event timer or
		// blocking logging path is added to business goroutines.
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case data, ok := <-out.queue:
				if !ok {
					if reportSuppressed() {
						_ = reportDropped(true)
					}
					return
				}
				if !reportDropped(false) || !write(data) {
					return
				}
			case <-tick.C:
				if !reportSuppressed() || !reportDropped(false) {
					return
				}
			}
		}
	}()
	return out
}

// Configure is used during startup, before request workers are started. Flags
// override environment defaults; malformed values fail without echoing them.
func (out *logOutput) Configure(level, format string) error {
	level = strings.ToLower(strings.TrimSpace(level))
	format = strings.ToLower(strings.TrimSpace(format))
	var threshold slog.Level
	switch level {
	case "", "info": threshold, level = logInfo, "info"
	case "debug": threshold = logDebug
	case "warn": threshold = logWarn
	case "error": threshold = logError
	default: return errors.New("log-level must be debug, info, warn or error")
	}
	if format == "" { format = "text" }
	if format != "text" && format != "json" {
		return errors.New("log-format must be text or json")
	}
	out.mu.Lock()
	out.level, out.format = threshold, format
	out.mu.Unlock()
	return nil
}

func (out *logOutput) Options() (level, format string) {
	out.mu.Lock()
	defer out.mu.Unlock()
	return strings.ToLower(out.level.String()), out.format
}

func (out *logOutput) Enabled(level slog.Level) bool {
	if out == nil || out.failed.Load() { return false }
	out.mu.Lock()
	defer out.mu.Unlock()
	return !out.closed && level >= out.level
}

// Only fixed messages and explicitly redacted metadata may be supplied. Raw
// errors are reduced to type names; request/response bodies must never be passed.
func (out *logOutput) encode(level slog.Level, event, message string, fields map[string]any) []byte {
	out.mu.Lock()
	format := out.format
	out.mu.Unlock()
	var buffer bytes.Buffer
	options := &slog.HandlerOptions{
		Level: logDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format("2006-01-02T15:04:05.000Z07:00"))
			}
			return a
		},
	}
	var handler slog.Handler = slog.NewTextHandler(&buffer, options)
	if format == "json" { handler = slog.NewJSONHandler(&buffer, options) }
	record := slog.NewRecord(time.Now(), level, message, 0)
	record.AddAttrs(slog.String("component", out.component), slog.Int("pid", out.pid), slog.String("event", event))
	keys := make([]string, 0, len(fields))
	for key := range fields {
		switch key {
		case "time", "level", "msg", "component", "pid", "event": continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := fields[key]
		if err, ok := value.(error); ok { value = fmt.Sprintf("%T", err) }
		record.AddAttrs(slog.Any(key, value))
	}
	if handler.Handle(context.Background(), record) != nil { return nil }
	return buffer.Bytes()
}

func (out *logOutput) Record(level slog.Level, event, message string, fields map[string]any) {
	if !out.Enabled(level) { return }
	data := out.encode(level, event, message, fields)
	if len(data) == 0 || len(data) > maxLogBytes {
		out.dropped.Add(1)
		return
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.closed || out.failed.Load() { return }
	// Leave bounded room for warnings/errors when diagnostics are verbose.
	if level < logWarn && len(out.queue) >= logQueueSize-logReserve {
		out.dropped.Add(1)
		return
	}
	select {
	case out.queue <- data:
	default: out.dropped.Add(1)
	}
}

// Limited coalesces maintenance warnings only. Request outcomes and errors are
// never coalesced. The single writer reports repeats each minute and on Close.
func (out *logOutput) Limited(level slog.Level, event, message string, fields map[string]any) {
	if level != logWarn {
		out.Record(level, event, message, fields)
		return
	}
	if !out.Enabled(level) { return }
	out.mu.Lock()
	if out.closed || out.failed.Load() {
		out.mu.Unlock()
		return
	}
	previous := out.notices[event]
	now := time.Now()
	if !previous.at.IsZero() && now.Sub(previous.at) < time.Minute {
		previous.suppressed++
		out.notices[event] = previous
		out.mu.Unlock()
		return
	}
	previous.at, previous.level = now, level
	out.notices[event] = previous
	out.mu.Unlock()
	out.Record(level, event, message, fields)
}

func (out *logOutput) Close() {
	if out == nil { return }
	out.mu.Lock()
	if !out.closed {
		out.closed = true
		close(out.queue)
	}
	out.mu.Unlock()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-out.done:
	case <-timer.C:
	}
}

var stderrLog *logOutput

func operationLogFields(ctx context.Context, fields map[string]any) map[string]any {
	copy := make(map[string]any, len(fields)+2)
	for key, value := range fields { copy[key] = value }
	if ctx != nil {
		if op, _ := ctx.Value(diagnosticOperationKey{}).(*diagnosticOperation); op != nil {
			copy["id"], copy["operation"] = op.id, op.op
		}
	}
	return copy
}

func logEvent(ctx context.Context, level slog.Level, event, message string, fields map[string]any) {
	if stderrLog.Enabled(level) {
		stderrLog.Record(level, event, message, operationLogFields(ctx, fields))
	}
}

func logLimited(ctx context.Context, level slog.Level, event, message string, fields map[string]any) {
	if stderrLog.Enabled(level) {
		stderrLog.Limited(level, event, message, operationLogFields(ctx, fields))
	}
}

// Called only after the IPC writer confirms the complete terminal line was
// written. Admission still releases at handoff. This is not a parent/client ACK,
// and successful HTTP transport is not proof of model-level success.
func logTerminal(op *operation, terminal message) {
	fields := map[string]any{
		"id": op.id, "operation": op.name,
		"elapsedMs": time.Since(op.started).Milliseconds(),
	}
	if terminal.Reusable != nil { fields["reusable"] = *terminal.Reusable }
	if terminal.Error != nil {
		if op.errorClass != "" { fields["errorClass"] = op.errorClass }
		fields["code"] = terminal.Error.Code
		fields["reason"] = terminal.Error.Message // locally constructed, redacted IPC message
		level, event, text := logError, "operation_failed", "原生操作失败"
		switch terminal.Error.Code {
		case "CANCELLED":
			level, event, text = logInfo, "operation_cancelled", "原生操作已取消"
		case "INVALID_INPUT", "INVALID_RERUN", "BUSY":
			level, event, text = logWarn, "operation_rejected", "原生操作被拒绝"
		}
		stderrLog.Record(level, event, text, fields)
		return
	}
	switch op.name {
	case "init":
		if state, ok := terminal.Data.(map[string]any); ok {
			for _, key := range []string{"capacity", "pages", "benefitStatus", "benefitTier"} { fields[key] = state[key] }
		}
		stderrLog.Record(logInfo, "runtime_ready", "原生运行时已就绪", fields)
	case "request":
		level, text := logInfo, "上游响应传输结束，终态已写入 IPC"
		if result, ok := terminal.Data.(map[string]any); ok {
			fields["status"], fields["persistence"] = result["status"], result["persistence"]
			if status, ok := result["status"].(int); ok && status >= 300 {
				level, text = logWarn, "上游返回非成功状态，终态已写入 IPC"
			}
		}
		stderrLog.Record(level, "request_complete", text, fields)
	case "validate_session":
		if result, ok := terminal.Data.(*sessionValidationResult); ok {
			fields["state"], fields["reason"] = result.State, result.Reason
			fields["persistence"] = result.Persistence
			level := logInfo
			if result.State != "valid" { level = logWarn }
			stderrLog.Record(level, "session_checked", "在线会话检查结束", fields)
		}
	}
}
