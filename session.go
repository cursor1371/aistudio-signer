package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const studioOrigin = "https://aistudio.google.com"

// stateCookie is the canonical persisted format. Negative expires means session;
// a leading domain dot identifies a domain cookie rather than a host-only cookie.
type stateCookie struct {
	Name string `json:"name"`
	Value string `json:"value"`
	Domain string `json:"domain"`
	Path string `json:"path"`
	Expires float64 `json:"expires"`
	HTTPOnly bool `json:"httpOnly"`
	Secure bool `json:"secure"`
	SameSite string `json:"sameSite,omitempty"`
	PartitionKey json.RawMessage `json:"partitionKey,omitempty"`
}

// Ordered state follows the reference's CookieHeader/MergeSetCookieHeaders:
// longer paths first, equal paths in original order, replacements in place.
// There is no second CookieJar with a different selection or creation order.
type accountSession struct {
	mu            sync.Mutex
	persistMu     sync.Mutex // serializes snapshots and commits, never HTTP selection
	savedHash     [32]byte
	persisted     bool
	storageHash   [32]byte
	storagePersisted bool
	path          string
	root          map[string]json.RawMessage
	cookies       []stateCookie
	storage       map[string]string // imported origins overlaid by pageStorage
	pageStorage   map[string]string
	storageLoaded bool

	// One account-owned save can outlive a caller's wait. There is no save queue.
	saveMu        sync.Mutex
	saving        *sessionSave
	lastSave      string
	lastSaveAt    time.Time
}

const pageStorageFile = "spidermonkey-storage.json"

func cookieKey(c stateCookie) string {
	return strings.TrimPrefix(c.Domain, ".") + "\n" + c.Path + "\n" + c.Name
}

// importedCookie covers both Cookie-Editor and Playwright exports. Import-only
// attributes are normalized once; they are not added to the runtime cookie model.
type importedCookie struct {
	Name           string          `json:"name"`
	Value          *string         `json:"value"`
	Domain         string          `json:"domain"`
	Path           string          `json:"path"`
	Expires        *float64        `json:"expires"`
	ExpirationDate *float64        `json:"expirationDate"`
	Session        bool            `json:"session"`
	HostOnly       *bool           `json:"hostOnly"`
	HTTPOnly       bool            `json:"httpOnly"`
	Secure         bool            `json:"secure"`
	SameSite       string          `json:"sameSite"`
	PartitionKey   json.RawMessage `json:"partitionKey"`
	Partitioned    bool            `json:"partitioned"`
}

func parseAccountCookies(raw []byte) (map[string]json.RawMessage, []stateCookie, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(raw), []byte{0xef, 0xbb, 0xbf}))
	if len(raw) == 0 {
		return nil, nil, failure("INVALID_STATE", "Account state is empty.")
	}
	root := make(map[string]json.RawMessage)
	cookieData := raw
	switch raw[0] {
	case '[':
		root["origins"] = json.RawMessage("[]")
	case '{':
		if json.Unmarshal(raw, &root) != nil || root == nil {
			return nil, nil, failure("INVALID_STATE", "Invalid account state JSON object.")
		}
		cookieData = root["cookies"]
	default:
		return nil, nil, failure("INVALID_STATE", "Account state must be a cookie array or a storage-state object.")
	}
	var imported []json.RawMessage
	if json.Unmarshal(cookieData, &imported) != nil || len(imported) == 0 {
		return nil, nil, failure("INVALID_STATE", "Account state requires a nonempty, valid cookies array.")
	}

	cookies := make([]stateCookie, 0, len(imported))
	positions := make(map[string]int, len(imported))
	skipped := 0
	for _, entry := range imported {
		var item importedCookie
		if json.Unmarshal(entry, &item) != nil || bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
			var identity struct { Name string `json:"name"` }
			_ = json.Unmarshal(entry, &identity)
			if authenticationCookie(identity.Name) {
				return nil, nil, failure("INVALID_STATE", "An authentication cookie has invalid attributes.")
			}
			skipped++
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(item.Domain))
		host := strings.TrimPrefix(domain, ".")
		if !googleHost(host) {
			continue
		}
		if item.Name == "" || item.Value == nil {
			if authenticationCookie(item.Name) {
				return nil, nil, failure("INVALID_STATE", "Authentication cookie name and value must be strings.")
			}
			skipped++
			continue
		}
		partition := bytes.TrimSpace(item.PartitionKey)
		if item.Partitioned || len(partition) > 0 &&
			!bytes.Equal(partition, []byte("null")) && !bytes.Equal(partition, []byte(`""`)) {
			if authenticationCookie(item.Name) {
				return nil, nil, failure("INVALID_STATE", "Partitioned authentication cookies are not supported.")
			}
			skipped++
			continue
		}
		if item.HostOnly != nil {
			domain = host
			if !*item.HostOnly {
				domain = "." + host
			}
		}
		path := item.Path
		if path == "" {
			path = "/"
		}
		expires := float64(-1)
		switch {
		case item.Session:
		case item.Expires != nil:
			expires = *item.Expires
		case item.ExpirationDate != nil:
			expires = *item.ExpirationDate
		}
		if expires < 0 {
			expires = -1
		}
		// http.Cookie permits expiry years through 9999. Check before converting
		// float64 seconds to int64; preserve valid fractional Unix seconds.
		if expires >= 253402300800 {
			if authenticationCookie(item.Name) {
				return nil, nil, failure("INVALID_STATE", "Authentication cookie expiry is outside the supported range.")
			}
			skipped++
			continue
		}
		c := stateCookie{
			Name: item.Name, Value: *item.Value, Domain: domain, Path: path,
			Expires: expires, HTTPOnly: item.HTTPOnly, Secure: item.Secure,
			SameSite: sameSiteName(parseSameSite(item.SameSite)),
		}
		// Normalize duplicates before dropping expired entries. A later expired
		// entry must not resurrect an earlier cookie with the same identity.
		key := cookieKey(c)
		if index, exists := positions[key]; exists {
			cookies[index] = c
		} else {
			positions[key] = len(cookies)
			cookies = append(cookies, c)
		}
	}
	if skipped != 0 {
		logEvent(nil, logWarn, "cookie_entries_skipped", "已跳过不支持的非认证 Cookie 条目", map[string]any{"count": skipped})
	}
	return root, cookies, nil
}

// Do not silently ignore malformed credentials or unpartition them. Optional
// browser/analytics cookies can be omitted without fabricating a session.
func authenticationCookie(name string) bool {
	switch name {
	case "SAPISID", "APISID", "SID", "HSID", "SSID", "SIDCC",
		"__Secure-1PAPISID", "__Secure-3PAPISID", "__Secure-1PSID", "__Secure-3PSID",
		"__Secure-1PSIDCC", "__Secure-3PSIDCC", "__Secure-1PSIDTS", "__Secure-3PSIDTS":
		return true
	}
	return false
}

func loadSession(path string) (*accountSession, error) {
	raw, err := os.ReadFile(path)
	if err != nil { return nil, failure("INVALID_STATE", "Cannot read account state.") }
	root, cookies, err := parseAccountCookies(raw)
	if err != nil { return nil, err }
	s := &accountSession{path: path, root: root, storage: map[string]string{}, pageStorage: map[string]string{}}
	var origins []struct {
		Origin string `json:"origin"`
		LocalStorage []struct { Name string `json:"name"`; Value string `json:"value"` } `json:"localStorage"`
	}
	if data := root["origins"]; len(data) > 0 && json.Unmarshal(data, &origins) != nil {
		return nil, failure("INVALID_STATE", "Invalid origins in account state.")
	}
	for _, origin := range origins {
		if origin.Origin == studioOrigin {
			for _, item := range origin.LocalStorage { s.storage[item.Name] = item.Value }
		}
	}
	// The separate page store wins over imported origin values, as in open().
	pageRaw, pageErr := os.ReadFile(filepath.Join(filepath.Dir(path), pageStorageFile))
	if pageErr == nil {
		if json.Unmarshal(pageRaw, &s.pageStorage) != nil || s.pageStorage == nil {
			return nil, failure("INVALID_STATE", "Invalid page local-storage file.")
		}
		s.storageLoaded = true
		for key, value := range s.pageStorage { s.storage[key] = value }
	} else if !os.IsNotExist(pageErr) {
		return nil, failure("INVALID_STATE", "Cannot read page local-storage file.")
	}
	nowSeconds := cookieSeconds(time.Now())
	skipped := 0
	for _, c := range cookies {
		host := strings.TrimPrefix(c.Domain, ".")
		if !strings.HasPrefix(c.Path, "/") {
			if authenticationCookie(c.Name) { return nil, failure("INVALID_STATE", "Invalid authentication cookie path.") }
			skipped++
			continue
		}
		if c.Expires >= 0 && c.Expires <= nowSeconds { continue }
		native := &http.Cookie{Name:c.Name, Value:c.Value, Path:c.Path, Secure:c.Secure, HttpOnly:c.HTTPOnly, SameSite:parseSameSite(c.SameSite)}
		if strings.HasPrefix(c.Domain, ".") { native.Domain = c.Domain }
		if c.Expires >= 0 {
			seconds := int64(c.Expires)
			native.Expires = time.Unix(seconds, int64((c.Expires-float64(seconds))*1e9))
		}
		if native.Valid() != nil {
			if authenticationCookie(c.Name) { return nil, failure("INVALID_STATE", "Invalid authentication cookie.") }
			skipped++
			continue
		}
		if native.Domain != "" {
			if suffix, _ := publicsuffix.PublicSuffix(host); suffix == host { continue }
		}
		s.cookies = append(s.cookies, c)
	}
	if skipped != 0 {
		logEvent(nil, logWarn, "cookie_entries_invalid", "已跳过属性非法的非认证 Cookie 条目", map[string]any{"count": skipped})
	}
	if _, err := s.authorization(); err != nil { return nil, err }
	return s, nil
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict": return http.SameSiteStrictMode
	case "lax": return http.SameSiteLaxMode
	case "none", "no_restriction": return http.SameSiteNoneMode
	default: return http.SameSiteDefaultMode
	}
}

func sameSiteName(value http.SameSite) string {
	switch value {
	case http.SameSiteStrictMode: return "Strict"
	case http.SameSiteLaxMode: return "Lax"
	case http.SameSiteNoneMode: return "None"
	default: return ""
	}
}

func cookieSeconds(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func cookieMatches(c stateCookie, u *url.URL, now float64) bool {
	if c.Value == "" || c.Expires >= 0 && c.Expires <= now || c.Secure && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	domain := strings.TrimPrefix(c.Domain, ".")
	// Keep host-only isolation even though the reference treats both forms as
	// domain cookies. Never broaden the imported credential scope.
	if host != domain && !(strings.HasPrefix(c.Domain, ".") && strings.HasSuffix(host, "."+domain)) {
		return false
	}
	path := u.EscapedPath()
	if path == "" { path = "/" }
	return path == c.Path || strings.HasPrefix(path, c.Path) &&
		(strings.HasSuffix(c.Path, "/") || len(path) > len(c.Path) && path[len(c.Path)] == '/')
}

func (s *accountSession) Cookies(u *url.URL) []*http.Cookie {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cookiesLocked(u, cookieSeconds(time.Now()))
}

func (s *accountSession) cookiesLocked(u *url.URL, now float64) []*http.Cookie {
	var selected []stateCookie
	for _, c := range s.cookies {
		if cookieMatches(c, u, now) { selected = append(selected, c) }
	}
	sort.SliceStable(selected, func(i, j int) bool { return len(selected[i].Path) > len(selected[j].Path) })
	out := make([]*http.Cookie, 0, len(selected))
	for _, c := range selected { out = append(out, &http.Cookie{Name: c.Name, Value: c.Value}) }
	return out
}

// SetCookies is shared by initialization, VM resource loads and generation.
func (s *accountSession) SetCookies(u *url.URL, cookies []*http.Cookie) {
	host := strings.ToLower(u.Hostname())
	if !googleHost(host) { return }
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		if c.Partitioned || c.Valid() != nil { continue }
		domain := strings.ToLower(c.Domain)
		if domain == "" { domain = host } else {
			domain = strings.TrimPrefix(domain, ".")
			if host != domain && !strings.HasSuffix(host, "."+domain) { continue }
			if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain { continue }
			domain = "." + domain
		}
		path := c.Path
		if !strings.HasPrefix(path, "/") {
			path = u.EscapedPath()
			if i := strings.LastIndex(path, "/"); i > 0 { path = path[:i] } else { path = "/" }
		}
		value := stateCookie{Name:c.Name, Value:c.Value, Domain:domain, Path:path, Expires:-1, HTTPOnly:c.HttpOnly, Secure:c.Secure, SameSite:sameSiteName(c.SameSite)}
		if !c.Expires.IsZero() { value.Expires = cookieSeconds(c.Expires) }
		if c.MaxAge > 0 {
			// Max-Age takes precedence; cap at the supported persisted date.
			value.Expires = min(cookieSeconds(now)+float64(c.MaxAge), 253402300799)
		}
		key, index := cookieKey(value), -1
		for i, existing := range s.cookies {
			if cookieKey(existing) == key { index = i; break }
		}
		if c.MaxAge < 0 || value.Expires >= 0 && value.Expires <= cookieSeconds(now) {
			if index >= 0 { s.cookies = append(s.cookies[:index], s.cookies[index+1:]...) }
		} else if index >= 0 {
			s.cookies[index] = value
		} else {
			s.cookies = append(s.cookies, value)
		}
	}
}

func (s *accountSession) authorization() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizationLocked(time.Now())
}

// requestCredentials selects both headers from the same state and timestamp.
// The lock is released before network I/O; resource requests remain unsigned.
func (s *accountSession) requestCredentials(u *url.URL, authenticated bool) (cookie, auth string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if authenticated {
		auth, err = s.authorizationLocked(now)
		if err != nil { return "", "", err }
	}
	var parts []string
	for _, c := range s.cookiesLocked(u, cookieSeconds(now)) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), auth, nil
}

func (s *accountSession) authorizationLocked(now time.Time) (string, error) {
	u, _ := url.Parse(studioOrigin + "/")
	values := map[string]string{}
	for _, c := range s.cookiesLocked(u, cookieSeconds(now)) {
		if _, ok := values[c.Name]; !ok { values[c.Name] = c.Value }
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	var parts []string
	for _, item := range [][2]string{{"SAPISIDHASH","SAPISID"},{"SAPISID1PHASH","__Secure-1PAPISID"},{"SAPISID3PHASH","__Secure-3PAPISID"}} {
		value := values[item[1]]
		if value == "" { return "", failure("AUTH_REQUIRED", "Account session is missing a required authentication cookie.") }
		sum := sha1.Sum([]byte(stamp + " " + value + " " + studioOrigin))
		parts = append(parts, item[0]+" "+stamp+"_"+hex.EncodeToString(sum[:]))
	}
	return strings.Join(parts, " "), nil
}

func (s *accountSession) documentCookie() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, _ := url.Parse(studioOrigin + "/")
	now := cookieSeconds(time.Now())
	var parts []string
	for _, c := range s.cookies {
		if !c.HTTPOnly && cookieMatches(c, u, now) { parts = append(parts, c.Name+"="+c.Value) }
	}
	return strings.Join(parts, "; ")
}

func (s *accountSession) storageSnapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.storage))
	for key, value := range s.storage { out[key] = value }
	return out
}

func (s *accountSession) pageStorageValue(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pageStorage[key]
}

func (s *accountSession) setPageStorage(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Runtime state is authoritative. Disk snapshots are committed by save().
	s.pageStorage[key] = value
	s.storage[key] = value
}

func (s *accountSession) save() (err error) {
	// Serialize commits before taking the snapshot so an older save cannot
	// overwrite a newer one. A concurrent Cookie update remains for the next save.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	defer func() {
		s.saveMu.Lock()
		previous := s.lastSave
		s.lastSave, s.lastSaveAt = "saved", time.Now().UTC()
		if err != nil { s.lastSave = "failed" }
		s.saveMu.Unlock()
		if err == nil && previous == "failed" {
			logEvent(nil, logInfo, "persistence_recovered", "账号状态持久化已恢复", nil)
		}
	}()
	s.mu.Lock()
	cookies := make([]stateCookie, 0, len(s.cookies))
	now := cookieSeconds(time.Now())
	for _, c := range s.cookies {
		if c.Expires < 0 || c.Expires > now {
			cookies = append(cookies, c)
		}
	}
	root := make(map[string]json.RawMessage, len(s.root)+1)
	for key, value := range s.root {
		root[key] = value
	}
	storage := make(map[string]string, len(s.pageStorage))
	for key, value := range s.pageStorage { storage[key] = value }
	s.mu.Unlock()

	raw, err := json.Marshal(cookies)
	if err != nil {
		return err
	}
	root["cookies"] = raw
	if _, exists := root["origins"]; !exists {
		root["origins"] = json.RawMessage("[]")
	}
	data, err := json.Marshal(root)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !s.persisted || hash != s.savedHash {
		if err := writePrivateBytes(s.path, data); err != nil { return err }
		s.savedHash, s.persisted = hash, true
	}
	storageData, err := json.Marshal(storage)
	if err != nil { return err }
	storageHash := sha256.Sum256(storageData)
	if !s.storagePersisted || storageHash != s.storageHash {
		if err := writePrivateBytes(filepath.Join(filepath.Dir(s.path), pageStorageFile), storageData); err != nil { return err }
		s.storageHash, s.storagePersisted = storageHash, true
	}
	return nil
}

type sessionSave struct {
	done chan struct{}
	err  error // published by closing done
}

// persist bounds only the caller's wait, not generation. A stalled disk owns
// at most one task per account; updates stay in memory for a later save/close.
func (s *accountSession) persist(ctx context.Context) string {
	if ctx.Err() != nil { return "deferred" }
	s.saveMu.Lock()
	if previous := s.saving; previous != nil {
		select {
		case <-previous.done:
		default:
			s.saveMu.Unlock()
			return "deferred" // its snapshot may predate this caller's updates
		}
	}
	pending := &sessionSave{done: make(chan struct{})}
	s.saving = pending
	s.saveMu.Unlock()
	go func() {
		pending.err = s.save()
		if pending.err != nil {
			logLimited(nil, logWarn, "persistence_failed", "账号状态保存失败，内存会话仍保留", map[string]any{"code": diagnosticError(pending.err)})
		}
		close(pending.done)
	}()
	select {
	case <-pending.done:
		if pending.err != nil { return "failed" }
		return "saved"
	case <-ctx.Done():
		return "deferred"
	}
}

func (s *accountSession) persistenceStatus() map[string]any {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	pending := false
	if s.saving != nil {
		select { case <-s.saving.done: default: pending = true }
	}
	status := s.lastSave
	if status == "" { status = "not_saved" }
	return map[string]any{"lastResult": status, "checkedAt": s.lastSaveAt, "pending": pending}
}

// Called only after all producers have stopped, before releasing the directory
// lock. The existing process shutdown budget bounds a stalled filesystem.
func (s *accountSession) waitPersistence() {
	s.saveMu.Lock()
	pending := s.saving
	s.saveMu.Unlock()
	if pending != nil { <-pending.done }
}

func writePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil { return err }
	return writePrivateBytes(path, data)
}

func writePrivateBytes(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".native-state-*")
	if err != nil { return err }
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil { _, err = f.Write(data) }
	if err == nil { err = f.Sync() }
	closed := f.Close()
	if err != nil { return err }
	if closed != nil { return closed }
	if err = os.Rename(f.Name(), path); err != nil { return fmt.Errorf("commit state: %w",err) }
	return nil
}
