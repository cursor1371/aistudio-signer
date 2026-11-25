package main

import (
	"encoding/json"

	"local/aistudio-signer/waa"
)

// Observation is separate from forwarding. Large or unrecognized elements are
// still forwarded byte-for-byte; only local stage observation is incomplete.
const observedElementLimit = 8 << 20

type responseObserver struct {
	vm                       *waa.Runtime
	rerun                    bool
	rootSeen, rootClosed     bool
	expectValue, afterComma  bool
	active, quoted, escaped bool
	depth                    int
	primitive                bool
	oversized                bool
	buffer                   []byte
	invalid                  bool
	skipped                  int
	reads                    int
	thought, call, text      bool
}

func newResponseObserver(vm *waa.Runtime, rerun bool) *responseObserver {
	return &responseObserver{vm: vm, rerun: rerun, expectValue: true}
}

func jsonSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func (o *responseObserver) feed(data []byte) {
	if o.invalid || len(data) == 0 {
		return
	}
	firstThought, firstCall, firstAnswer, content := false, false, false, false
	complete := func() {
		if o.oversized {
			o.skipped++
		} else if !json.Valid(o.buffer) {
			o.invalid = true
		} else {
			t, c, a, grown := o.element(o.buffer)
			firstThought = firstThought || t
			firstCall = firstCall || c
			firstAnswer = firstAnswer || a
			content = content || grown
		}
		o.buffer = o.buffer[:0]
		o.active, o.primitive, o.oversized = false, false, false
		o.expectValue = false
	}
	for i := 0; i < len(data) && !o.invalid; i++ {
		c := data[i]
		if !o.rootSeen {
			if jsonSpace(c) {
				continue
			}
			if c != '[' {
				o.invalid = true
				break
			}
			o.rootSeen = true
			continue
		}
		if o.rootClosed {
			if !jsonSpace(c) {
				o.invalid = true
			}
			continue
		}
		if !o.active {
			if jsonSpace(c) {
				continue
			}
			if !o.expectValue {
				switch c {
				case ',':
					o.expectValue, o.afterComma = true, true
				case ']':
					o.rootClosed = true
				default:
					o.invalid = true
				}
				continue
			}
			if c == ']' && !o.afterComma {
				o.rootClosed = true
				continue
			}
			if c == ']' || c == ',' {
				o.invalid = true
				break
			}
			o.active, o.afterComma = true, false
			o.depth, o.quoted, o.escaped = 0, false, false
			o.primitive = c != '{' && c != '[' && c != '"'
		}
		if o.primitive && (jsonSpace(c) || c == ',' || c == ']') {
			complete()
			i-- // Reprocess the separator outside the value.
			continue
		}
		if !o.oversized {
			if len(o.buffer) == observedElementLimit {
				o.buffer = nil
				o.oversized = true
			} else {
				o.buffer = append(o.buffer, c)
			}
		}
		if o.quoted {
			if o.escaped {
				o.escaped = false
			} else if c == '\\' {
				o.escaped = true
			} else if c == '"' {
				o.quoted = false
				if o.depth == 0 {
					complete()
				}
			}
			continue
		}
		switch c {
		case '"':
			o.quoted = true
		case '{', '[':
			o.depth++
		case '}', ']':
			o.depth--
			if o.depth == 0 {
				complete()
			}
		}
	}
	// The first read, first thought/call block and the first answer after
	// thought during an explicit rerun do not generate a scrolling notification.
	if o.reads > 0 && content && !firstThought && !firstCall &&
		!(o.rerun && firstAnswer) && (o.text || !o.thought) && !o.invalid && o.skipped == 0 && o.vm != nil {
		o.vm.Streamed()
	}
	o.reads++
}

func (o *responseObserver) element(raw []byte) (firstThought, firstCall, firstAnswer, content bool) {
	var frame map[string]json.RawMessage
	if json.Unmarshal(raw, &frame) != nil || frame == nil {
		return
	}
	var candidates []struct {
		Index   int `json:"index"`
		Content struct {
			Parts []map[string]json.RawMessage `json:"parts"`
		} `json:"content"`
	}
	if json.Unmarshal(frame["candidates"], &candidates) != nil {
		return
	}
	for _, candidate := range candidates {
		if candidate.Index != 0 {
			continue // One local page turn; all candidates still go to stdout.
		}
		for _, part := range candidate.Content.Parts {
			var thought bool
			_ = json.Unmarshal(part["thought"], &thought)
			if thought {
				firstThought = firstThought || !o.thought
				o.thought = true
				content = true
			}
			if !isNull(alias(part, "functionCall", "function_call")) {
				firstCall = firstCall || !o.call
				o.call = true
				content = true
			}
			if textValue(part["text"]) != "" {
				content = true
				if !thought && isNull(alias(part, "thoughtSignature", "thought_signature")) && o.thought && !o.text {
					o.text, firstAnswer = true, true
				}
			}
		}
	}
	return
}

func (o *responseObserver) complete() bool {
	return !o.invalid && o.skipped == 0 && o.rootSeen && o.rootClosed && !o.active
}
