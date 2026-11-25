package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var modelPattern = regexp.MustCompile(`^models/[A-Za-z0-9][A-Za-z0-9._-]*$`)

type requestParams struct {
	Body   json.RawMessage `json:"body"`
	// Rerun is an explicit local action, never a Google request field or retry.
	Rerun bool `json:"rerun,omitempty"`
}

type jsonRequest struct {
	body                  []byte
	fields                map[string]json.RawMessage
	contents              []json.RawMessage
	roles                 []string
	model, digest, prompt string
	functionResult        string
	isFunctionResult      bool
	rerun                 bool
	comparison            []string
	settingsComparison    string
}

// object reads one level without reconstructing nested business fields.
func object(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, failure("INVALID_INPUT", "Expected a JSON object.")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, failure("INVALID_INPUT", "Invalid JSON object.")
		}
		name, ok := key.(string)
		if !ok {
			return nil, failure("INVALID_INPUT", "Invalid JSON key.")
		}
		if _, exists := out[name]; exists {
			return nil, failure("INVALID_INPUT", "Duplicate JSON field.")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, failure("INVALID_INPUT", "Invalid JSON value.")
		}
		out[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, failure("INVALID_INPUT", "Unclosed JSON object.")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, failure("INVALID_INPUT", "Unexpected trailing JSON.")
	}
	return out, nil
}

func alias(fields map[string]json.RawMessage, names ...string) json.RawMessage {
	for _, name := range names {
		if v, ok := fields[name]; ok {
			return v
		}
	}
	return nil
}

func textValue(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func parseRequest(params requestParams) (*jsonRequest, error) {
	if !utf8.Valid(params.Body) {
		return nil, failure("INVALID_INPUT", "Request must contain valid UTF-8.")
	}
	fields, err := object(params.Body)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"requestSnapshot", "request_snapshot"} {
		if _, exists := fields[name]; exists {
			return nil, failure("INVALID_INPUT", "requestSnapshot is reserved.")
		}
	}
	r := &jsonRequest{
		body: bytes.TrimSpace(params.Body), fields: fields,
		model: textValue(fields["model"]), rerun: params.Rerun,
	}
	if !modelPattern.MatchString(r.model) {
		return nil, failure("INVALID_INPUT", "model must be a models/<id> string.")
	}
	if json.Unmarshal(fields["contents"], &r.contents) != nil || r.contents == nil {
		return nil, failure("INVALID_INPUT", "contents must be an array.")
	}
	var values []string
	for i, content := range r.contents {
		c, err := object(content)
		if err != nil {
			return nil, err
		}
		role := textValue(c["role"])
		r.roles = append(r.roles, role)
		var parts []json.RawMessage
		if json.Unmarshal(c["parts"], &parts) != nil || parts == nil {
			return nil, failure("INVALID_INPUT", "Content parts must be an array.")
		}
		var texts []string
		for _, raw := range parts {
			p, err := object(raw)
			if err != nil {
				return nil, err
			}
			var contribution string
			if v, exists := p["text"]; exists && !isNull(v) {
				if json.Unmarshal(v, &contribution) != nil {
					return nil, failure("INVALID_INPUT", "Part text must be a string.")
				}
				if contribution != "" {
					texts = append(texts, contribution)
				}
			} else if data := alias(p, "inlineData", "inline_data"); !isNull(data) {
				b, err := object(data)
				if err != nil {
					return nil, err
				}
				if json.Unmarshal(b["data"], &contribution) != nil {
					return nil, failure("INVALID_INPUT", "inlineData.data must be a string.")
				}
			} else if drive := alias(p, "driveFile", "drive_file"); !isNull(drive) {
				b, err := object(drive)
				if err != nil {
					return nil, err
				}
				if json.Unmarshal(b["id"], &contribution) != nil {
					return nil, failure("INVALID_INPUT", "driveFile.id must be a string.")
				}
			}
			values = append(values, contribution)

			// Match wireFunctionResult: exactly one Part in the last user turn.
			// Mixed or parallel results remain untouched and use the generic path.
			if i == len(r.contents)-1 && role == "user" && len(parts) == 1 {
				if v := alias(p, "functionResponse", "function_response"); !isNull(v) {
					f, err := object(v)
					if err != nil {
						return nil, err
					}
					response := f["response"]
					if b := bytes.TrimSpace(response); len(b) > 0 && b[0] == '{' {
						r.functionResult = canonical(response)
						r.isFunctionResult = r.functionResult != ""
					}
				}
			}
		}
		// GeneratePrompt inspects the final turn, not the last user found in history.
		if i == len(r.contents)-1 && role == "user" {
			r.prompt = strings.Join(texts, " ")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(values, " ")))
	r.digest = hex.EncodeToString(sum[:])
	return r, nil
}

// These comparison views are request-local and never replace wire bytes.
func (r *jsonRequest) contentKeys() []string {
	if r.comparison == nil {
		r.comparison = make([]string, len(r.contents))
		for i, content := range r.contents {
			r.comparison[i] = canonical(content)
		}
	}
	return r.comparison
}

func (r *jsonRequest) settingsKey() string {
	if r.settingsComparison == "" {
		r.settingsComparison = r.model + "\n" + canonical(alias(r.fields, "generationConfig", "generation_config")) +
			"\n" + canonical(alias(r.fields, "systemInstruction", "system_instruction")) +
			"\n" + canonical(r.fields["tools"])
	}
	return r.settingsComparison
}

func (r *jsonRequest) userRounds() int {
	rounds := 0
	for _, role := range r.roles {
		if role == "user" {
			rounds++
		}
	}
	return rounds
}

func (r *jsonRequest) submitRounds() int {
	return max(r.userRounds()-1, 1)
}

// signedBody inserts only the new root member; existing business bytes are kept.
func (r *jsonRequest) signedBody(proof string) []byte {
	value, _ := json.Marshal(proof)
	body := make([]byte, 0, len(r.body)+len(value)+24)
	body = append(body, r.body[:len(r.body)-1]...)
	body = append(body, `,"requestSnapshot":`...)
	body = append(body, value...)
	return append(body, '}')
}

// contentText is the system-instruction view: text Parts joined by newlines.
// Non-text Parts do not contribute a synthetic blank line.
func contentText(raw json.RawMessage) string {
	var content struct {
		Parts []map[string]json.RawMessage `json:"parts"`
	}
	if json.Unmarshal(raw, &content) != nil {
		return ""
	}
	var texts []string
	for _, part := range content.Parts {
		var text string
		if value := part["text"]; !isNull(value) && json.Unmarshal(value, &text) == nil {
			texts = append(texts, text)
		}
	}
	return strings.Join(texts, "\n")
}

// canonical is used for local comparisons only, never for the HTTP body.
func canonical(raw json.RawMessage) string {
	if isNull(raw) {
		return ""
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return ""
	}
	b, _ := json.Marshal(value)
	return string(b)
}
