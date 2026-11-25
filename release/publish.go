package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type githubClient struct {
	ctx    context.Context
	http   *http.Client
	repo   string
	token  string
}

// The authenticated client never follows redirects or prints response bodies.
// Only the two fixed GitHub API hosts below receive the publishing token.
func (g *githubClient) call(method, endpoint string, body io.Reader, size int64, contentType string, output any, missingOK bool) error {
	var input io.Reader
	if body != nil {
		// The caller owns file handles. Also prevent automatic replay of writes.
		input = struct{ io.Reader }{body}
	}
	request, err := http.NewRequestWithContext(g.ctx, method, endpoint, input)
	if err != nil {
		return err
	}
	if request.URL.Scheme != "https" || request.URL.User != nil ||
		(request.URL.Host != "api.github.com" && request.URL.Host != "uploads.github.com") {
		return errors.New("unexpected GitHub API endpoint")
	}
	request.Header.Set("Authorization", "Bearer "+g.token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "aistudio-signer-release")
	if body != nil {
		request.Header.Set("Content-Type", contentType)
		request.ContentLength = size
	}
	response, err := g.http.Do(request)
	if err != nil {
		return errors.New("GitHub API request failed; check network and proxy settings")
	}
	defer response.Body.Close()
	if response.StatusCode == 404 && missingOK {
		return os.ErrNotExist
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("GitHub API %s %s returned HTTP %d", method, request.URL.Path, response.StatusCode)
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<20))
		return err
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output)
}

func (g *githubClient) endpoint(suffix string) string {
	return "https://api.github.com/repos/" + g.repo + suffix
}

func (g *githubClient) json(method, endpoint string, value, output any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return g.call(method, endpoint, bytes.NewReader(data), int64(len(data)), "application/json", output, false)
}

func (g *githubClient) tagCommit(tag string) (string, error) {
	type object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	var ref struct {
		Object object `json:"object"`
	}
	if err := g.call("GET", g.endpoint("/git/ref/tags/"+url.PathEscape(tag)), nil, 0, "", &ref, false); err != nil {
		return "", err
	}
	for depth := 0; depth < 5; depth++ {
		if !commitPattern.MatchString(ref.Object.SHA) {
			return "", errors.New("invalid GitHub tag object")
		}
		if ref.Object.Type == "commit" {
			return ref.Object.SHA, nil
		}
		if ref.Object.Type != "tag" {
			return "", errors.New("release tag does not resolve to a commit")
		}
		var annotated struct {
			Object object `json:"object"`
		}
		if err := g.call("GET", g.endpoint("/git/tags/"+ref.Object.SHA), nil, 0, "", &annotated, false); err != nil {
			return "", err
		}
		ref.Object = annotated.Object
	}
	return "", errors.New("too many annotated tag indirections")
}

func (g *githubClient) requireNewRelease(tag string) error {
	err := g.call("GET", g.endpoint("/releases/tags/"+url.PathEscape(tag)), nil, 0, "", nil, true)
	if err == nil {
		return errors.New("release already exists; refusing to overwrite it")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The tag lookup need not expose drafts. Authenticated listing includes
	// drafts; reject an unfinished publication instead of creating a second one.
	for page := 1; ; page++ {
		var releases []struct {
			Tag string `json:"tag_name"`
		}
		endpoint := g.endpoint("/releases?per_page=100&page=" + strconv.Itoa(page))
		if err := g.call("GET", endpoint, nil, 0, "", &releases, false); err != nil {
			return err
		}
		for _, release := range releases {
			if release.Tag == tag {
				return errors.New("a release or draft already exists for this tag")
			}
		}
		if len(releases) < 100 {
			return nil
		}
	}
}

func publish(ctx context.Context, directory string) error {
	repo, token, tag := os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_REF_NAME")
	if os.Getenv("GITHUB_EVENT_NAME") != "push" || os.Getenv("GITHUB_REF_TYPE") != "tag" || !tagPattern.MatchString(tag) {
		return errors.New("publication is allowed only for a version-tag push job")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(repo) || token == "" {
		return errors.New("GITHUB_REPOSITORY and GH_TOKEN are required")
	}
	commit := os.Getenv("GITHUB_SHA")
	if !commitPattern.MatchString(commit) {
		return errors.New("GITHUB_SHA must identify the tagged commit")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	m, files, err := verifyBundle(directory, tag, repo, commit)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	g := &githubClient{ctx: ctx, http: client, repo: repo, token: token}
	remoteCommit, err := g.tagCommit(tag)
	if err != nil {
		return err
	}
	if remoteCommit != m.Commit {
		return errors.New("remote tag commit does not match the verified artifacts")
	}
	if err := g.requireNewRelease(tag); err != nil {
		return err
	}
	prerelease := strings.Contains(tag, "-")
	var created struct {
		ID int64 `json:"id"`
	}
	if err := g.json("POST", g.endpoint("/releases"), map[string]any{
		"tag_name": tag, "target_commitish": m.Commit, "name": tag,
		"draft": true, "prerelease": prerelease, "generate_release_notes": true,
	}, &created); err != nil {
		return err
	}
	if created.ID <= 0 {
		return errors.New("GitHub did not return a valid draft release id")
	}
	published := false
	defer func() {
		if !published {
			fmt.Fprintln(os.Stderr, "Publication stopped. Inspect and remove the incomplete draft before retrying; no automatic overwrite is performed.")
		}
	}()
	id := strconv.FormatInt(created.ID, 10)
	for _, name := range files {
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		contentType := "application/octet-stream"
		if strings.HasSuffix(name, ".zip") {
			contentType = "application/zip"
		} else if strings.HasSuffix(name, ".json") {
			contentType = "application/json"
		}
		endpoint := "https://uploads.github.com/repos/" + repo + "/releases/" + id + "/assets?name=" + url.QueryEscape(name)
		var asset struct {
			Name  string `json:"name"`
			State string `json:"state"`
			Size  int64  `json:"size"`
		}
		fmt.Fprintln(os.Stderr, "upload:", name)
		err = g.call("POST", endpoint, file, info.Size(), contentType, &asset, false)
		err = errors.Join(err, file.Close())
		if err != nil {
			return err
		}
		if asset.Name != name || asset.State != "uploaded" || asset.Size != info.Size() {
			return fmt.Errorf("upload metadata mismatch: %s", name)
		}
	}
	latest := "true"
	if prerelease {
		latest = "false"
	}
	var result struct {
		Draft bool   `json:"draft"`
		Tag   string `json:"tag_name"`
		URL   string `json:"html_url"`
	}
	if err := g.json("PATCH", g.endpoint("/releases/"+id), map[string]any{
		"draft": false, "prerelease": prerelease, "make_latest": latest,
	}, &result); err != nil {
		return err
	}
	if result.Draft || result.Tag != tag {
		return errors.New("release publication state was not confirmed")
	}
	published = true
	fmt.Println("Published:", result.URL)
	return nil
}
