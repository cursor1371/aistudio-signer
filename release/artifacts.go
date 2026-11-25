package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// The executable carries detailed Go build information already. Package
// metadata contains only the identity needed to select and verify a release.
type releaseInfo struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	Protocol     int    `json:"protocol"`
	Target       string `json:"target"`
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binarySHA256"`
	SourceDirty  bool   `json:"sourceDirty,omitempty"`
}

type artifact struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Per-platform reports are CI handoff files, not public release attachments.
type platformReport struct {
	Version     string   `json:"version"`
	Commit      string   `json:"commit"`
	Protocol    int      `json:"protocol"`
	SourceDirty bool     `json:"sourceDirty,omitempty"`
	Artifact    artifact `json:"artifact"`
}

type manifest struct {
	Schema      int        `json:"schema"`
	Version     string     `json:"version"`
	Commit      string     `json:"commit"`
	Protocol    int        `json:"protocol"`
	Repository  string     `json:"repository"`
	SourceDirty bool       `json:"sourceDirty,omitempty"`
	Artifacts   []artifact `json:"artifacts"`
}

func validateFile(name, digest string, size int64) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != size || !hashPattern.MatchString(digest) {
		return fmt.Errorf("invalid artifact metadata: %s", filepath.Base(name))
	}
	actual, err := fileHash(name)
	if err != nil {
		return err
	}
	if actual != digest {
		return fmt.Errorf("artifact checksum mismatch: %s", filepath.Base(name))
	}
	return nil
}

// Run once in the platform build job. Later jobs verify the ZIP checksum,
// rather than repeatedly decompressing and re-reading every package entry.
func verifyArchive(name string, expected releaseInfo) error {
	z, err := zip.OpenReader(name)
	if err != nil {
		return err
	}
	defer z.Close()
	seen := make(map[string]bool)
	var total uint64
	for _, entry := range z.File {
		allowed := entry.Name == expected.Binary || entry.Name == "release-info.json" || slices.Contains(packageFiles, entry.Name)
		if !allowed || seen[entry.Name] || !entry.Mode().IsRegular() {
			return fmt.Errorf("unexpected package entry: %s", entry.Name)
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > 2<<30 || total+entry.UncompressedSize64 > 4<<30 {
			return errors.New("package exceeds verification limit")
		}
		total += entry.UncompressedSize64
		r, err := entry.Open()
		if err != nil {
			return err
		}
		switch entry.Name {
		case "release-info.json":
			data, readErr := io.ReadAll(io.LimitReader(r, (1<<20)+1))
			var embedded releaseInfo
			if readErr != nil || len(data) > 1<<20 || json.Unmarshal(data, &embedded) != nil || embedded != expected {
				err = errors.New("embedded release metadata mismatch")
			}
		case expected.Binary:
			h := sha256.New()
			_, err = io.Copy(h, r)
			if err == nil && hex.EncodeToString(h.Sum(nil)) != expected.BinarySHA256 {
				err = errors.New("embedded executable checksum mismatch")
			}
			if !strings.HasPrefix(expected.Target, "windows-") && entry.Mode()&0111 == 0 {
				err = errors.New("executable permission missing from ZIP")
			}
		default:
			_, err = io.Copy(io.Discard, r)
		}
		err = errors.Join(err, r.Close())
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name, err)
		}
	}
	if !seen["release-info.json"] || !seen[expected.Binary] {
		return errors.New("incomplete binary package")
	}
	return nil
}

// Hash while copying into the new staging directory: one read of each archive.
func copyCheckedArtifact(source, destination string, expected artifact) error {
	if !hashPattern.MatchString(expected.SHA256) || expected.Size <= 0 {
		return errors.New("invalid artifact checksum or size")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != expected.Size {
		return fmt.Errorf("artifact size or file type mismatch: %s", expected.Name)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	err = errors.Join(err, out.Close())
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return fmt.Errorf("artifact checksum mismatch: %s", expected.Name)
	}
	return nil
}

func (t *tool) assemble() error {
	ver, commit, _, err := t.metadata()
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(t.root, ".release-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	m := manifest{
		Schema: 2, Version: ver, Commit: commit, Protocol: t.lock.Protocol,
		Repository: os.Getenv("GITHUB_REPOSITORY"),
	}
	checksums := make(map[string]string)
	for _, target := range targets {
		name := productName + "-" + ver + "-" + target
		var report platformReport
		if err := readJSON(filepath.Join(t.root, "dist", name+".json"), &report); err != nil {
			return err
		}
		a := report.Artifact
		if report.Version != ver || report.Commit != commit || report.Protocol != m.Protocol ||
			a.Target != target || a.Name != name+".zip" {
			return fmt.Errorf("platform report mismatch: %s", target)
		}
		if err := copyCheckedArtifact(filepath.Join(t.root, "dist", a.Name), filepath.Join(stage, a.Name), a); err != nil {
			return err
		}
		m.SourceDirty = m.SourceDirty || report.SourceDirty
		m.Artifacts = append(m.Artifacts, a)
		checksums[a.Name] = a.SHA256
	}
	if err := writeJSON(filepath.Join(stage, "release-manifest.json"), m); err != nil {
		return err
	}
	checksums["release-manifest.json"], err = fileHash(filepath.Join(stage, "release-manifest.json"))
	if err != nil {
		return err
	}
	names := make([]string, 0, len(checksums))
	for name := range checksums {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", checksums[name], name)
	}
	if err := os.WriteFile(filepath.Join(stage, "SHA256SUMS"), []byte(sums.String()), 0644); err != nil {
		return err
	}

	destination := filepath.Join(t.root, "publish")
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	// Replace only this release's files; commit the manifest and sums last.
	for _, a := range m.Artifacts {
		if err := os.Rename(filepath.Join(stage, a.Name), filepath.Join(destination, a.Name)); err != nil {
			return err
		}
	}
	for _, name := range []string{"release-manifest.json", "SHA256SUMS"} {
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	fmt.Println("All five platforms assembled:", destination)
	return nil
}

// The privileged job checks the received files against the manifest and sums
// once. It never decompresses archives or uploads unlisted local files.
func verifyBundle(dir, tag, repository, commit string) (manifest, []string, error) {
	var m manifest
	if err := readJSON(filepath.Join(dir, "release-manifest.json"), &m); err != nil {
		return m, nil, err
	}
	if m.Schema != 2 || m.Version != tag || m.Commit != commit || m.Repository != repository ||
		m.Protocol < 1 || len(m.Artifacts) != len(targets) {
		return m, nil, errors.New("publication manifest does not match the tag job")
	}
	expected := make(map[string]artifact)
	seenTargets := make(map[string]bool)
	for _, a := range m.Artifacts {
		if validTarget(a.Target) != nil || seenTargets[a.Target] ||
			a.Name != productName+"-"+tag+"-"+a.Target+".zip" ||
			!hashPattern.MatchString(a.SHA256) || a.Size <= 0 {
			return m, nil, errors.New("invalid platform metadata in publication")
		}
		seenTargets[a.Target] = true
		expected[a.Name] = a
	}
	for _, name := range []string{"release-manifest.json", "SHA256SUMS"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return m, nil, err
		}
		if !info.Mode().IsRegular() {
			return m, nil, fmt.Errorf("publication entry is not a regular file: %s", name)
		}
		if name == "release-manifest.json" {
			expected[name] = artifact{Name: name, Size: info.Size()}
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return m, nil, err
	}
	listed := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		digest, name, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "  ")
		a, exists := expected[name]
		if !ok || !hashPattern.MatchString(digest) || !exists || listed[name] ||
			(a.SHA256 != "" && a.SHA256 != digest) {
			return m, nil, errors.New("invalid checksum inventory")
		}
		if err := validateFile(filepath.Join(dir, name), digest, a.Size); err != nil {
			return m, nil, err
		}
		listed[name] = true
	}
	if len(listed) != len(expected) {
		return m, nil, errors.New("incomplete checksum inventory")
	}
	files := make([]string, 0, len(expected)+1)
	for name := range expected {
		files = append(files, name)
	}
	files = append(files, "SHA256SUMS")
	sort.Strings(files)
	return m, files, nil
}
