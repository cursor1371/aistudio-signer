package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Resource selection and navigation rules are adapted from v0.3.13
// page_resources.go. HTTP bodies are loaded, not executed as frontend scripts.
type pageResourceKind int

const (
	pageStylesheet pageResourceKind = iota
	pagePreloadScript
	pageScript
	frameRedirectionLimit = 20
	imageAccept = "image/avif,image/jxl,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
)

type pageResource struct {
	url  string
	kind pageResourceKind
}

type pageIcon struct {
	url   string
	width int
	rich  bool
}

type pageDocument struct {
	resources []pageResource
	icons     []pageIcon
}

var iconSizePattern = regexp.MustCompile(`(?i)^([1-9][0-9]*)x[1-9][0-9]*$`)

func parsePageDocument(body []byte, pageURL string) pageDocument {
	base, _ := url.Parse(pageURL)
	resolve := func(raw string) string {
		if strings.TrimSpace(raw) == "" { return "" }
		u, err := base.Parse(strings.TrimSpace(raw))
		if err != nil || !allowedURL(u.String()) { return "" }
		return u.String()
	}
	var document pageDocument
	preloaded := map[string]bool{}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	noscript := false
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken { return document }
		token := tokenizer.Token()
		if token.DataAtom == atom.Noscript {
			noscript = kind == html.StartTagToken
			continue
		}
		if noscript || kind != html.StartTagToken && kind != html.SelfClosingTagToken { continue }
		attributes := map[string]string{}
		for _, a := range token.Attr { attributes[a.Key] = a.Val }
		switch token.DataAtom {
		case atom.Base:
			if href, exists := attributes["href"]; exists {
				if u, err := base.Parse(href); err == nil && allowedURL(u.String()) { base = u }
			}
		case atom.Link:
			href := resolve(attributes["href"])
			if href == "" { continue }
			rels := strings.Fields(strings.ToLower(attributes["rel"]))
			switch {
			case slices.Contains(rels, "stylesheet"):
				document.resources = append(document.resources, pageResource{href, pageStylesheet})
			case slices.Contains(rels, "preload") && strings.EqualFold(attributes["as"], "script"):
				document.resources = append(document.resources, pageResource{href, pagePreloadScript})
				preloaded[href] = true
			default:
				rich := slices.Contains(rels, "apple-touch-icon") || slices.Contains(rels, "apple-touch-icon-precomposed") || slices.Contains(rels, "fluid-icon")
				if rich || slices.Contains(rels, "icon") {
					document.icons = append(document.icons, pageIcon{href, iconWidth(attributes["sizes"]), rich})
				}
			}
		case atom.Script:
			_, async := attributes["async"]
			_, deferred := attributes["defer"]
			source := resolve(attributes["src"])
			if source == "" || async || deferred || attributes["type"] == "module" || preloaded[source] { continue }
			document.resources = append(document.resources, pageResource{source, pageScript})
		}
	}
}

func iconWidth(sizes string) int {
	for _, size := range strings.Fields(sizes) {
		if strings.EqualFold(size, "any") { return -1 }
		if match := iconSizePattern.FindStringSubmatch(size); match != nil {
			width, err := strconv.Atoi(match[1])
			if err == nil { return width }
		}
	}
	return -1
}

func selectPageIcons(icons []pageIcon, preferredWidth int) (rich, tab string) {
	var largestRich, bestSized, fallback *pageIcon
	for i := range icons {
		icon := &icons[i]
		if icon.rich || icon.width >= 96 {
			if largestRich == nil || largestRich.width < icon.width { largestRich = icon }
		} else { fallback = icon }
		if icon.width >= preferredWidth && (bestSized == nil || bestSized.width >= icon.width) { bestSized = icon }
	}
	if largestRich != nil { rich = largestRich.url }
	if bestSized != nil { tab = bestSized.url } else if fallback != nil { tab = fallback.url }
	return
}

func fetchSite(target string) string {
	u, err := url.Parse(target)
	if err != nil { return "cross-site" }
	host := strings.ToLower(u.Hostname())
	if host == "aistudio.google.com" { return "same-origin" }
	if host == "google.com" || strings.HasSuffix(host, ".google.com") { return "same-site" }
	return "cross-site"
}

func subresourceHeaders(target, accept, destination, priority string) http.Header {
	h := http.Header{}
	h.Set("Accept", accept)
	h.Set("Referer", studioOrigin+"/")
	site := fetchSite(target)
	if site == "cross-site" { h.Set("Sec-Fetch-Storage-Access", "none") }
	h.Set("Sec-Fetch-Dest", destination)
	h.Set("Sec-Fetch-Mode", "no-cors")
	h.Set("Sec-Fetch-Site", site)
	if priority != "" { h.Set("Priority", priority) }
	return h
}

func (e *engine) loadDocumentResources(ctx context.Context, document pageDocument) error {
	errs := make([]error, len(document.resources))
	var group sync.WaitGroup
	for i, resource := range document.resources {
		accept, destination, priority := "*/*", "script", "u=2"
		switch resource.kind {
		case pageStylesheet:
			accept, destination = "text/css,*/*;q=0.1", "style"
		case pagePreloadScript:
			priority = "u=1"
		}
		h := subresourceHeaders(resource.url, accept, destination, priority)
		group.Add(1)
		go func() {
			defer group.Done()
			errs[i] = e.fetchCached(ctx, resource.url, h)
		}()
	}
	group.Wait()
	if ctx.Err() != nil { return ctx.Err() }
	return errors.Join(errs...)
}

// Resource metadata stores only the HTTP validators used by this loader.
func (e *engine) fetchCached(ctx context.Context, target string, headers http.Header) (err error) {
	if !allowedURL(target) { return failure("INVALID_ENDPOINT", "Resource origin is not allowed.") }
	entry, fresh := e.pageCache.lookup(target, time.Now())
	mode, status := "network", 0
	defer func() {
		if e.audit != nil {
			e.audit.record(ctx, "resource_cache", map[string]any{
				"destination": headers.Get("Sec-Fetch-Dest"), "mode": mode,
				"httpStatus": status, "errorClass": diagnosticError(err),
			})
		}
	}()
	if fresh { mode = "fresh"; return nil }
	h := headers.Clone()
	if entry.LastModified != "" { h.Set("If-Modified-Since", entry.LastModified) }
	if entry.ETag != "" { h.Set("If-None-Match", entry.ETag) }
	if entry.LastModified != "" || entry.ETag != "" { mode = "conditional" }
	response, err := e.do(ctx, http.MethodGet, target, nil, h)
	if err != nil { return err }
	status = response.StatusCode
	if _, err = readBounded(response, bootstrapLimit); err != nil { return err }
	if status != http.StatusOK && status != http.StatusNotModified {
		return failure("RESOURCE_HTTP", "A declared page resource returned an unsuccessful response.")
	}
	return e.pageCache.store(target, response, time.Now())
}

// Icons are optional, as in the reference, but owned by the component lifetime
// rather than an uncancellable background context. No account/profile RPCs run.
func (e *engine) loadPageIcons(document pageDocument) {
	ratio, ok := numberValue(e.profile.Window["devicePixelRatio"])
	if !ok || ratio <= 0 { ratio = 1 }
	rich, tab := selectPageIcons(document.icons, 16*int(math.Ceil(ratio)))
	for _, target := range []string{rich, tab} {
		if target == "" { continue }
		e.background.Add(1)
		go func() {
			defer e.background.Done()
			ctx, cancel := context.WithTimeout(e.lifetime, 30*time.Second)
			defer cancel()
			if err := e.fetchCached(ctx, target, subresourceHeaders(target, imageAccept, "image", "u=6")); err != nil && e.audit != nil {
				e.audit.record(ctx, "optional_resource", map[string]any{"kind": "icon", "errorClass": diagnosticError(err)})
			}
		}()
	}
}

// A terminal HTTP error document still fires a frame load event. accepted here
// means navigation finished, not authentication or model access succeeded.
func (e *engine) navigateFrame(ctx context.Context, target string) (status, redirects int, err error) {
	for {
		if !allowedURL(target) { return status, redirects, failure("INVALID_ENDPOINT", "Frame navigation left the allowed origins.") }
		h := http.Header{}
		h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		h.Set("Referer", studioOrigin+"/")
		h.Set("Upgrade-Insecure-Requests", "1")
		h.Set("Sec-Fetch-Dest", "iframe")
		h.Set("Sec-Fetch-Mode", "navigate")
		h.Set("Sec-Fetch-Site", fetchSite(target))
		h.Set("Priority", "u=4")
		response, requestErr := e.do(ctx, http.MethodGet, target, nil, h)
		if requestErr != nil { return status, redirects, requestErr }
		status = response.StatusCode
		// Navigation needs completion, not its document contents. Stream-discard
		// within the callback deadline instead of allocating the whole document.
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil { return status, redirects, readErr }
		if closeErr != nil { return status, redirects, closeErr }
		if status < 300 || status >= 400 { return status, redirects, nil }
		if redirects >= frameRedirectionLimit {
			return status, redirects, failure("RESOURCE_REDIRECT", "Frame navigation exceeded its redirect limit.")
		}
		next, locationErr := response.Location()
		if locationErr != nil { return status, redirects, failure("RESOURCE_REDIRECT", "Frame redirect has no valid location.") }
		target = next.String()
		redirects++
	}
}

func (e *engine) loadFrame(parent context.Context, address string) (accepted bool) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	started := time.Now()
	status, redirects, err := e.navigateFrame(ctx, address)
	accepted = err == nil
	if e.audit != nil {
		e.audit.record(ctx, "resource_callback", map[string]any{
			"destination": "iframe", "accepted": accepted, "httpStatus": status,
			"redirectCount": redirects, "elapsedMs": time.Since(started).Milliseconds(),
			"errorClass": diagnosticError(err),
		})
	}
	return
}

func (e *engine) loadImage(parent context.Context, address string) (accepted bool) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	started := time.Now()
	status := 0
	var err error
	defer func() {
		if e.audit != nil {
			e.audit.record(ctx, "resource_callback", map[string]any{
				"destination": "image", "accepted": accepted, "httpStatus": status,
				"redirectResponse": status >= 300 && status < 400,
				"elapsedMs": time.Since(started).Milliseconds(), "errorClass": diagnosticError(err),
			})
		}
	}()
	h := subresourceHeaders(address, imageAccept, "image", "u=5, i")
	response, err := e.do(ctx, http.MethodGet, address, nil, h)
	if err != nil { return false }
	status = response.StatusCode
	body, err := readBounded(response, 4<<20)
	if err != nil { return false }
	return status == http.StatusOK && strings.HasPrefix(response.Header.Get("Content-Type"), "image/") && len(body) > 0
}
