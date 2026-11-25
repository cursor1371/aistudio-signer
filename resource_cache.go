package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const pageCacheFile = "spidermonkey-cache.json"

type pageCacheEntry struct {
	Received     time.Time `json:"received"`
	Date         string    `json:"date,omitempty"`
	Age          string    `json:"age,omitempty"`
	CacheControl string    `json:"cacheControl,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
	ETag         string    `json:"etag,omitempty"`
}

type pageCache struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	path      string
	entries   map[string]pageCacheEntry
	loaded    bool
	savedHash [32]byte
	persisted bool
	diskDisabled bool // failed/corrupt files never block a valid network resource
}

func loadPageCache(statePath string) (*pageCache, error) {
	cache := &pageCache{
		path:    filepath.Join(filepath.Dir(statePath), pageCacheFile),
		entries: make(map[string]pageCacheEntry),
	}
	raw, err := os.ReadFile(cache.path)
	if os.IsNotExist(err) {
		return cache, nil
	}
	if err != nil {
		cache.diskDisabled = true
		logLimited(nil, logWarn, "resource_cache_unreadable", "资源缓存不可读取，改用内存缓存", map[string]any{"code": diagnosticError(err)})
		return cache, nil
	}
	var entries map[string]json.RawMessage
	invalid := 0
	if json.Unmarshal(raw, &entries) != nil || entries == nil {
		invalid = 1
	} else {
		cache.loaded = true
		for key, data := range entries {
			var entry pageCacheEntry
			if json.Unmarshal(data, &entry) != nil || entry.Received.IsZero() {
				invalid++
				continue
			}
			cache.entries[key] = entry
		}
	}
	if invalid != 0 {
		// Preserve the incompatible file before any subsequent cache commit.
		// If archiving fails, use memory only rather than overwrite evidence.
		archive := cache.path + ".invalid-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if err := os.Rename(cache.path, archive); err != nil {
			cache.diskDisabled = true
		}
		logLimited(nil, logWarn, "resource_cache_invalid", "资源缓存含无效条目，将按需重新获取", map[string]any{"count": invalid, "diskDisabled": cache.diskDisabled})
	}
	return cache, nil
}

func cacheMaxAge(value string) (time.Duration, bool) {
	var result time.Duration
	found := false
	for _, directive := range strings.Split(strings.ToLower(value), ",") {
		name, argument, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch name {
		case "no-cache", "no-store":
			return 0, false
		case "max-age":
			seconds, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(argument), `"`), 10, 64)
			if err != nil || seconds < 0 || seconds > int64((1<<63-1)/time.Second) {
				return 0, false
			}
			result, found = time.Duration(seconds)*time.Second, true
		}
	}
	return result, found
}

func (c *pageCache) lookup(target string, now time.Time) (pageCacheEntry, bool) {
	c.mu.Lock()
	entry, exists := c.entries[target]
	c.mu.Unlock()
	life, cacheable := cacheMaxAge(entry.CacheControl)
	if !exists || !cacheable || entry.Received.IsZero() || entry.Received.After(now) {
		return entry, false
	}
	var age time.Duration
	if date, err := http.ParseTime(entry.Date); err == nil && entry.Received.After(date) {
		age = entry.Received.Sub(date)
	}
	if seconds, err := strconv.ParseInt(entry.Age, 10, 64); err == nil && seconds > 0 {
		if seconds > int64((1<<63-1)/time.Second) {
			return entry, false
		}
		age = max(age, time.Duration(seconds)*time.Second)
	}
	return entry, age < life && now.Sub(entry.Received) < life-age
}

func (c *pageCache) store(target string, response *http.Response, received time.Time) error {
	// Preserve commit order without holding the lookup lock during file I/O.
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.Lock()
	entry := c.entries[target]
	h := response.Header
	if response.StatusCode == http.StatusOK {
		entry = pageCacheEntry{LastModified: h.Get("Last-Modified"), ETag: h.Get("ETag")}
	} else if response.StatusCode != http.StatusNotModified || entry.Received.IsZero() {
		c.mu.Unlock()
		return failure("CACHE_RESPONSE", "Resource response cannot update the cache.")
	}
	entry.Received, entry.Date, entry.Age = received, h.Get("Date"), h.Get("Age")
	if value := h.Get("Cache-Control"); value != "" || response.StatusCode == http.StatusOK {
		entry.CacheControl = value
	}
	if value := h.Get("ETag"); value != "" {
		entry.ETag = value
	}
	if value := h.Get("Last-Modified"); value != "" {
		entry.LastModified = value
	}
	if strings.Contains(strings.ToLower(entry.CacheControl), "no-store") {
		delete(c.entries, target)
	} else {
		c.entries[target] = entry
	}
	snapshot := make(map[string]pageCacheEntry, len(c.entries))
	for key, value := range c.entries {
		snapshot[key] = value
	}
	c.mu.Unlock()

	if c.diskDisabled { return nil }
	data, err := json.Marshal(snapshot)
	if err != nil {
		c.diskDisabled = true
		logLimited(nil, logWarn, "resource_cache_encode_failed", "资源缓存序列化失败，继续使用内存缓存", map[string]any{"code": diagnosticError(err)})
		return nil
	}
	hash := sha256.Sum256(data)
	if c.persisted && hash == c.savedHash {
		return nil
	}
	if err := writePrivateBytes(c.path, data); err != nil {
		c.diskDisabled = true
		logLimited(nil, logWarn, "resource_cache_save_failed", "资源缓存保存失败，继续使用内存缓存", map[string]any{"code": diagnosticError(err)})
		return nil
	}
	c.savedHash, c.persisted = hash, true
	return nil
}
