package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const (
	protocolVersion = 3
	maxMessageBytes = 64 << 20 // IPC input buffer limit; parent must include the newline in its size check.
	outputQueueSize = 16
	outputTimeout = 30 * time.Second
	shutdownGrace = 5 * time.Second
)

// Release metadata is informational; clients negotiate the IPC contract only.
var releaseVersion = "dev"
var releaseCommit = "unknown"

type command struct {
	ID string `json:"id"`
	Op string `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
	Target string `json:"target,omitempty"`
}

type ipcError struct {
	Code string `json:"code"`
	Message string `json:"message"`
}
func (e *ipcError) Error() string { return e.Message }
func failure(code, message string) error { return &ipcError{Code: code, Message: message} }

type message struct {
	ID string `json:"id,omitempty"`
	Type string `json:"type"`
	Data any `json:"data,omitempty"`
	Error *ipcError `json:"error,omitempty"`
	Reusable *bool `json:"reusable,omitempty"` // required on every result/end/error; absent on nonterminal messages
}

type input struct { line []byte; err error }
type operationResult struct { owner *operation; data any; err error }
type operation struct {
	id, name string
	started time.Time
	errorClass string // redacted terminal diagnostic, dispatcher-owned
	ctx context.Context
	cancel context.CancelFunc
	finished chan struct{}
	finishing bool // dispatcher-owned
	cancelRequested bool // explicit IPC cancellation, including after a deadline
	retirementCancelled bool // cleanup cancellation must not hide an initiating error
}
type outputMessage struct {
	value message
	owner *operation
	terminal bool
}

func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil { return failure("INVALID_INPUT", "Invalid JSON or unsupported input field.") }
	var extra any
	if err := d.Decode(&extra); err != io.EOF { return failure("INVALID_INPUT", "Expected exactly one JSON value.") }
	return nil
}

func errorMessage(id string, err error) message {
	var public *ipcError
	switch {
	case errors.As(err, &public):
	case errors.Is(err, context.DeadlineExceeded):
		public = &ipcError{"TIMEOUT", "Operation deadline exceeded; no automatic retry."}
	case errors.Is(err, context.Canceled):
		public = &ipcError{"CANCELLED", "Operation cancelled."}
	default:
		public = &ipcError{"NATIVE_ERROR", "Native runtime failed; inspect the stage and restart if required."}
	}
	return message{ID: id, Type: "error", Error: public}
}

func readInput(ctx context.Context, out chan<- input) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), maxMessageBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 { continue }
		select {
		case out <- input{line: bytes.Clone(line)}:
		case <-ctx.Done(): return
		}
	}
	err := scanner.Err()
	if err == nil { err = io.EOF }
	select { case out <- input{err: err}: case <-ctx.Done(): }
}

func main() {
	stderrLog = newLogOutput(os.Stderr, "aistudio-signer")
	err := run()
	if err != nil {
		fields := map[string]any{"code": diagnosticError(err)}
		var local *ipcError
		if errors.As(err, &local) { fields["reason"] = local.Message }
		stderrLog.Record(logError, "process_failed", "原生组件异常退出", fields)
	} else {
		stderrLog.Record(logInfo, "stopped", "原生组件已停止", nil)
	}
	stderrLog.Close()
	if err != nil { os.Exit(1) }
}

func run() error {
	showVersion := flag.Bool("version", false, "Print build metadata as JSON and exit without loading an account")
	configPath := flag.String("config", "config.json", "Path to the account configuration")
	level := flag.String("log-level", os.Getenv("LOG_LEVEL"), "Log level: debug, info (default), warn, error")
	format := flag.String("log-format", os.Getenv("LOG_FORMAT"), "Log format: text (default), json")
	flag.Parse()
	if *showVersion {
		if flag.NArg() != 0 { return failure("INVALID_CONFIG", "Unexpected positional argument.") }
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"component": "aistudio-signer", "version": releaseVersion, "commit": releaseCommit,
			"protocol": protocolVersion, "goVersion": runtime.Version(),
			"os": runtime.GOOS, "arch": runtime.GOARCH,
		})
	}
	if err := stderrLog.Configure(*level, *format); err != nil {
		return failure("INVALID_CONFIG", err.Error())
	}
	if flag.NArg() != 0 { return failure("INVALID_CONFIG", "Unexpected positional argument.") }
	cfg, err := loadConfig(*configPath)
	if err != nil { return err }
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	selectedLevel, selectedFormat := stderrLog.Options()
	stderrLog.Record(logInfo, "started", "原生组件已启动，等待 IPC 初始化", map[string]any{
		"protocol": protocolVersion, "capacity": cfg.Capacity,
		"logLevel": selectedLevel, "logFormat": selectedFormat,
	})
	x := newExecutor(cfg, ctx, newDiagnostics(stderrLog.Enabled(logDebug), stderrLog))
	incoming := make(chan input, 1)
	events := make(chan outputMessage)
	results := make(chan operationResult)
	stuck := make(chan *operation)
	go readInput(ctx, incoming)
	jobs, writes := startOutput(ctx)

	active := make(map[string]*operation)
	var workers sync.WaitGroup
	initStarted, initialized, retiring := false, false, false
	validatingSession := false
	requests := 0
	pending := make([]outputMessage, 0, outputQueueSize)
	var writing *outputMessage
	var writeTimer *time.Timer
	var writeDeadline <-chan time.Time
	var accountFailure <-chan struct{} = x.shared.failed
	var retirementTimer *time.Timer
	var retirementDeadline <-chan time.Time
	beginRetirement := func() {
		if retiring {
			return
		}
		retiring, accountFailure = true, nil
		x.shared.retire()
		logEvent(nil, logError, "account_retired", "账号执行器已退役，停止准入并排空已完成结果", nil)
		retirementTimer = time.NewTimer(shutdownGrace)
		retirementDeadline = retirementTimer.C
		for _, op := range active {
			if op.finishing {
				continue
			}
			select {
			case <-op.finished:
				// Native work is done; its result and preceding data still belong
				// to the parent even when another page retired the account.
			default:
				op.retirementCancelled = true
				op.cancel()
			}
		}
	}
	enqueue := func(value message) error {
		if len(pending) >= outputQueueSize+len(active) {
			return failure("OUTPUT_BLOCKED", "IPC control output is blocked; drain stdout.")
		}
		// Control replies, including rejected commands, have the same terminal
		// health contract as completed operations. This is process health, not
		// initialization readiness or authentication state.
		if value.Type == "result" || value.Type == "end" || value.Type == "error" {
			usable := !retiring && !x.broken.Load()
			value.Reusable = &usable
		}
		pending = append(pending, outputMessage{value: value})
		if value.Error != nil {
			logEvent(nil, logWarn, "command_rejected", "IPC 命令未执行", map[string]any{"id": value.ID, "code": value.Error.Code})
		}
		return nil
	}
	defer func() {
		cancelRun()
		if writeTimer != nil { writeTimer.Stop() }
		if retirementTimer != nil { retirementTimer.Stop() }
		for _, op := range active { op.cancel() }
		closed := make(chan struct{})
		go func() {
			workers.Wait()
			if err := x.close(); err != nil {
				logEvent(nil, logError, "cleanup_failed", "原生资源清理未完整完成", map[string]any{"code": diagnosticError(err)})
			}
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(shutdownGrace):
			logEvent(nil, logError, "cleanup_timeout", "清理期限已到，进程即将退出", nil)
		}
	}()
	_ = enqueue(message{Type: "hello", Data: map[string]any{
		"protocol": protocolVersion, "capacity": cfg.Capacity,
	}})

	for {
		if x.broken.Load() {
			beginRetirement()
		}
		if retiring && len(active) == 0 && writing == nil && len(pending) == 0 {
			return failure("RESTART_REQUIRED", "Account runtime is no longer reusable.")
		}
		// A cancelled request cannot block other IDs with unsent body messages.
		kept := pending[:0]
		for _, item := range pending {
			if item.owner != nil && !item.terminal && item.owner.ctx.Err() != nil { continue }
			kept = append(kept, item)
		}
		clear(pending[len(kept):])
		pending = kept
		if writing == nil && len(pending) == 0 && writeTimer != nil {
			writeTimer.Stop(); writeTimer, writeDeadline = nil, nil
		}
		var send chan<- message
		var next message
		if writing == nil && len(pending) > 0 {
			send, next = jobs, pending[0].value
			if writeTimer == nil { writeTimer = time.NewTimer(outputTimeout); writeDeadline = writeTimer.C }
		}
		var receiveEvents <-chan outputMessage
		if len(pending) < outputQueueSize { receiveEvents = events }
		select {
		case <-ctx.Done():
			logEvent(nil, logInfo, "stopping", "收到退出信号，正在取消操作并清理资源", nil)
			return nil
		case <-accountFailure:
			beginRetirement()
		case <-retirementDeadline:
			return failure("RESTART_REQUIRED", "Account runtime cleanup failed; process exiting.")
		case <-writeDeadline: return failure("OUTPUT_BLOCKED", "IPC output is blocked.")
		case send <- next:
			item := pending[0]
			pending[0] = outputMessage{}
			pending = pending[1:]
			writing = &item
			if item.terminal {
				// Per-ID native work and all earlier output have finished. Release
				// admission before the parent can receive this terminal line.
				if active[item.owner.id] == item.owner {
					delete(active, item.owner.id)
					if item.owner.name == "request" { requests-- }
					if item.owner.name == "validate_session" { validatingSession = false }
					if item.owner.name == "init" && item.value.Type == "result" { initialized = true }
				}
				item.owner.cancel()
			}
		case err := <-writes:
			if err != nil {
				logEvent(nil, logError, "ipc_write_failed", "IPC 输出写入失败，未确认结果交付", map[string]any{
					"id": writing.value.ID, "messageType": writing.value.Type,
					"code": diagnosticError(err),
				})
				return err
			}
			if writing.terminal {
				logTerminal(writing.owner, writing.value)
			}
			writeTimer.Stop(); writeTimer, writeDeadline = nil, nil
			writing = nil
			// Retirement exits only after all queued results have been written
			// or its shared drain deadline expires, never after the first error.
		case op := <-stuck:
			if active[op.id] != op || op.finishing { continue }
			select { case <-op.finished: continue; default: }
			op.finishing = true
			beginRetirement()
			terminal := errorMessage(op.id, failure("RESTART_REQUIRED", "Native operation did not stop after cancellation; process exiting."))
			usable := false
			terminal.Reusable = &usable
			pending = append(pending, outputMessage{value: terminal, owner: op, terminal: true})
		case item := <-receiveEvents:
			if active[item.owner.id] == item.owner && !item.owner.finishing && item.owner.ctx.Err() == nil {
				pending = append(pending, item)
			}
		case value := <-results:
			op := value.owner
			if active[op.id] != op || op.finishing { continue }
			if op.name == "validate_session" && op.cancelRequested {
				// A deadline is sticky in context.Err(); remember an explicit cancel
				// separately so it cannot publish a validation result afterwards.
				value.err = context.Canceled
			} else if cause := op.ctx.Err(); cause != nil && (!op.retirementCancelled || value.err == nil) {
				// Validation reports its bounded timeout as an observation. A result
				// completed before the deadline remains valid while queued for output.
				if !(op.name == "validate_session" && cause == context.DeadlineExceeded && value.err == nil && value.data != nil) {
					value.err = cause
				}
			}
			if op.name == "validate_session" && value.err == nil {
				observation := value.data.(*sessionValidationResult)
				x.mu.Lock()
				x.validation = observation
				x.mu.Unlock()
				validationCtx := x.audit.begin(op.ctx, command{ID: op.id, Op: op.name})
				x.audit.record(validationCtx, "session_validation", observation)
			}
			kind := "result"
			if op.name == "request" { kind = "end" }
			terminal := message{ID: op.id, Type: kind, Data: value.data}
			op.errorClass = diagnosticError(value.err)
			if value.err != nil { terminal = errorMessage(op.id, value.err) }
			op.finishing = true
			if x.broken.Load() {
				beginRetirement()
			}
			usable := !retiring && !x.broken.Load()
			terminal.Reusable = &usable
			// At most one reserved terminal per admitted operation.
			pending = append(pending, outputMessage{value: terminal, owner: op, terminal: true})
		case item := <-incoming:
			if item.err != nil {
				if item.err == io.EOF {
					logEvent(nil, logInfo, "stopping", "父进程已关闭输入，正在清理", nil)
					if retiring {
						incoming = nil
						continue
					}
					return nil
				}
				return failure("INPUT_FAILED", "IPC input failed or exceeded the message limit.")
			}
			var cmd command
			if err := decode(item.line, &cmd); err != nil {
				if err = enqueue(errorMessage("", err)); err != nil { return err }
				continue
			}
			if cmd.Op == "shutdown" {
				logEvent(nil, logInfo, "stopping", "收到 shutdown，正在清理", nil)
				if retiring {
					continue // a parent retirement must not discard queued terminals
				}
				return nil
			}
			if cmd.Op == "cancel" {
				if op := active[cmd.Target]; op != nil && !op.finishing {
					select {
					case <-op.finished:
						// Do not replace an already-completed result with cancellation.
					default:
						op.cancelRequested = true
						op.cancel()
					}
				}
				continue
			}
			if cmd.ID == "" {
				if err := enqueue(errorMessage("", failure("INVALID_INPUT", "id is required."))); err != nil { return err }
				continue
			}
			if active[cmd.ID] != nil { return failure("DUPLICATE_ID", "Duplicate active operation id.") }
			if cmd.Op == "status" {
				state := x.status()
				state["activeRequests"] = requests
				state["sessionValidationActive"] = validatingSession
				if err := enqueue(message{ID: cmd.ID, Type: "result", Data: state}); err != nil { return err }
				continue
			}
			var reject error
			switch {
			case retiring: reject = failure("RESTART_REQUIRED", "Account runtime is closing.")
			case cmd.Op == "init" && initStarted: reject = failure("ALREADY_INITIALIZED", "Initialization is allowed once per process.")
			case (cmd.Op == "request" || cmd.Op == "validate_session") && !initialized: reject = failure("NOT_INITIALIZED", "Wait for init before submitting requests or session validation.")
			case cmd.Op == "validate_session" && validatingSession: reject = failure("BUSY", "A session validation is already in progress; no validation queue.")
			case cmd.Op == "request" && requests >= cfg.Capacity: reject = failure("BUSY", "Account execution capacity is occupied; no internal request queue.")
			case cmd.Op != "init" && cmd.Op != "request" && cmd.Op != "validate_session": reject = failure("INVALID_INPUT", "Unsupported operation.")
			}
			if reject != nil {
				if err := enqueue(errorMessage(cmd.ID, reject)); err != nil { return err }
				continue
			}
			var opCtx context.Context
			var cancel context.CancelFunc
			if cmd.Op == "init" {
				initStarted = true
				opCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.InitTimeoutSeconds)*time.Second)
			} else if cmd.Op == "validate_session" {
				validatingSession = true
				opCtx, cancel = context.WithTimeout(ctx, sessionValidationTimeout)
			} else {
				requests++
				opCtx, cancel = context.WithCancel(ctx)
			}
			op := &operation{id: cmd.ID, name: cmd.Op, started: time.Now(), ctx: opCtx, cancel: cancel, finished: make(chan struct{})}
			if cmd.Op == "init" {
				logEvent(nil, logInfo, "initializing", "正在初始化账号运行时", map[string]any{"id": cmd.ID, "capacity": cfg.Capacity})
			}
			active[cmd.ID] = op
			workers.Add(1)
			go func() {
				defer workers.Done()
				emit := func(kind string, data any) error {
					if err := opCtx.Err(); err != nil { return err }
					select {
					case events <- outputMessage{value: message{ID: cmd.ID, Type: kind, Data: data}, owner: op}: return nil
					case <-opCtx.Done(): return opCtx.Err()
					}
				}
				data, err := x.execute(opCtx, cmd, emit)
				close(op.finished)
				select { case results <- operationResult{owner: op, data: data, err: err}: case <-ctx.Done(): }
			}()
			go func() {
				select { case <-op.finished: return; case <-opCtx.Done(): }
				timer := time.NewTimer(shutdownGrace)
				defer timer.Stop()
				select {
				case <-op.finished: return
				case <-ctx.Done(): return
				case <-timer.C:
				}
				select { case stuck <- op: case <-op.finished: case <-ctx.Done(): }
			}()
		}
	}
}

func startOutput(ctx context.Context) (chan<- message, <-chan error) {
	jobs := make(chan message)
	done := make(chan error, 1)
	go func() {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		for {
			select {
			case value := <-jobs:
				err := encoder.Encode(value)
				done <- err
				if err != nil { return }
			case <-ctx.Done(): return
			}
		}
	}()
	return jobs, done
}
