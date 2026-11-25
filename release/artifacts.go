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
	"reflect"
	"sort"
	"strings"
	"time"
)

type artifact struct {
	Target string    `json:"target"`
	Name   string    `json:"name"`
	SHA256 string    `json:"sha256"`
	Size   int64     `json:"size"`
	Build  buildInfo `json:"build"`
}

type sourceArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type manifest struct {
	Schema     int            `json:"schema"`
	Version    string         `json:"version"`
	Commit     string         `json:"commit"`
	Protocol   int            `json:"protocol"`
	Repository string         `json:"repository"`
	Artifacts  []artifact     `json:"artifacts"`
	Source     sourceArtifact `json:"source"`
}

func verifyChecks(checks []string) error {
	for _, expected := range []string{"native-engine", "version", "help", "ipc-no-init", "linkage"} {
		found := false
		for _, value := range checks {
			found = found || value == expected
		}
		if !found {
			return fmt.Errorf("missing release check: %s", expected)
		}
	}
	return nil
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

func verifyArchive(name string, report artifact) error {
	if err := validateFile(name, report.SHA256, report.Size); err != nil {
		return err
	}
	z, err := zip.OpenReader(name)
	if err != nil {
		return err
	}
	defer z.Close()
	seen := make(map[string]bool)
	metadataFound, binaryFound, licensesFound := false, false, false
	var total uint64
	for _, entry := range z.File {
		if _, err := safeArchivePath("package", entry.Name); err != nil {
			return err
		}
		if seen[entry.Name] || !entry.Mode().IsRegular() {
			return errors.New("duplicate or non-regular package entry")
		}
		// Local documentation is never a release input. Only declared package
		// files and collected dependency licenses are admitted.
		allowed := entry.Name == report.Build.Binary || entry.Name == "release-info.json" || strings.HasPrefix(entry.Name, "licenses/")
		for _, name := range packageFiles {
			allowed = allowed || entry.Name == name
		}
		if !allowed {
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
			var embedded buildInfo
			if readErr != nil || len(data) > 1<<20 || json.Unmarshal(data, &embedded) != nil || !reflect.DeepEqual(embedded, report.Build) {
				err = errors.New("embedded release metadata mismatch")
			}
			metadataFound = true
		case report.Build.Binary:
			h := sha256.New()
			_, err = io.Copy(h, r)
			if err == nil && hex.EncodeToString(h.Sum(nil)) != report.Build.BinarySHA256 {
				err = errors.New("embedded executable checksum mismatch")
			}
			if !strings.HasPrefix(report.Target, "windows-") && entry.Mode()&0111 == 0 {
				err = errors.New("executable permission missing from ZIP")
			}
			binaryFound = true
		default:
			_, err = io.Copy(io.Discard, r) // Also checks the ZIP CRC.
			licensesFound = licensesFound || strings.HasPrefix(entry.Name, "licenses/")
		}
		err = errors.Join(err, r.Close())
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name, err)
		}
	}
	if !metadataFound || !binaryFound || !licensesFound {
		return errors.New("incomplete binary package")
	}
	for _, name := range packageFiles {
		if !seen[name] {
			return fmt.Errorf("missing package file: %s", name)
		}
	}
	return nil
}

func (t *tool) assemble() error {
	if err := t.checkSources(); err != nil {
		return err
	}
	ver, commit, _, err := t.metadata()
	if err != nil {
		return err
	}
	destination := filepath.Join(t.root, "publish")
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("publish already exists or cannot be inspected")
	}
	stage, err := os.MkdirTemp(t.root, ".release-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	m := manifest{Schema: 1, Version: ver, Commit: commit, Protocol: t.lock.Protocol, Repository: os.Getenv("GITHUB_REPOSITORY")}
	for _, target := range targets {
		name := productName + "-" + ver + "-" + target
		var a artifact
		if err := readJSON(filepath.Join(t.root, "dist", name+".json"), &a); err != nil {
			return err
		}
		goos, arch, _ := strings.Cut(target, "-")
		if a.Target != target || a.Name != name+".zip" || a.Build.Target != target || a.Build.Version != ver || a.Build.Commit != commit || a.Build.Component != productName || a.Build.Protocol != t.lock.Protocol || a.Build.GoVersion != "go"+t.lock.Go || a.Build.OS != goos || a.Build.Arch != arch || a.Build.Binary != executable(target) || a.Build.SourceRepository != m.Repository || !reflect.DeepEqual(a.Build.SpiderMonkey, t.lock.Native) {
			return fmt.Errorf("platform report mismatch: %s", target)
		}
		if err := verifyChecks(a.Build.Checks); err != nil {
			return fmt.Errorf("%s: %w", target, err)
		}
		archive := filepath.Join(t.root, "dist", a.Name)
		if err := verifyArchive(archive, a); err != nil {
			return fmt.Errorf("%s: %w", target, err)
		}
		if err := copyFile(archive, filepath.Join(stage, a.Name), 0644); err != nil {
			return err
		}
		m.Artifacts = append(m.Artifacts, a)
	}
	m.Source.Name = productName + "-" + ver + "-source.zip"
	source := filepath.Join(stage, m.Source.Name)
	if _, err := t.run(nil, false, 5*time.Minute, "git", "archive", "--format=zip", "--prefix="+productName+"-"+ver+"/", "-o", source, commit); err != nil {
		return err
	}
	m.Source.SHA256, err = fileHash(source)
	if err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	m.Source.Size = info.Size()
	if err := writeJSON(filepath.Join(stage, "release-manifest.json"), m); err != nil {
		return err
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	var sums strings.Builder
	for _, entry := range entries {
		hash, err := fileHash(filepath.Join(stage, entry.Name()))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", hash, entry.Name())
	}
	if err := os.WriteFile(filepath.Join(stage, "SHA256SUMS"), []byte(sums.String()), 0644); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		return err
	}
	fmt.Println("All five platforms verified:", destination)
	return nil
}

// verifyBundle runs again in the write-privileged publication job. It checks
// exactly the expected filenames; unlisted files are never uploaded.
func verifyBundle(dir, tag, repository, commit string) (manifest, []string, error) {
	var m manifest
	if err := readJSON(filepath.Join(dir, "release-manifest.json"), &m); err != nil {
		return m, nil, err
	}
	if m.Schema != 1 || m.Version != tag || m.Commit != commit || m.Repository != repository || m.Protocol < 1 || len(m.Artifacts) != len(targets) {
		return m, nil, errors.New("publication manifest does not match the tag job")
	}
	expected := map[string]bool{"release-manifest.json": true, "SHA256SUMS": true}
	seenTargets := make(map[string]bool)
	for _, a := range m.Artifacts {
		goos, arch, _ := strings.Cut(a.Target, "-")
		if validTarget(a.Target) != nil || seenTargets[a.Target] || a.Name != productName+"-"+tag+"-"+a.Target+".zip" || a.Build.Target != a.Target || a.Build.Commit != commit || a.Build.Version != tag || a.Build.Component != productName || a.Build.OS != goos || a.Build.Arch != arch || a.Build.Protocol != m.Protocol || a.Build.SourceRepository != repository || a.Build.Binary != executable(a.Target) {
			return m, nil, errors.New("invalid platform metadata in publication")
		}
		if err := verifyChecks(a.Build.Checks); err != nil {
			return m, nil, err
		}
		seenTargets[a.Target], expected[a.Name] = true, true
		if err := verifyArchive(filepath.Join(dir, a.Name), a); err != nil {
			return m, nil, err
		}
	}
	if m.Source.Name != productName+"-"+tag+"-source.zip" {
		return m, nil, errors.New("invalid source artifact name")
	}
	expected[m.Source.Name] = true
	if err := validateFile(filepath.Join(dir, m.Source.Name), m.Source.SHA256, m.Source.Size); err != nil {
		return m, nil, err
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return m, nil, err
	}
	listed := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		hash, name, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "  ")
		if !ok || !hashPattern.MatchString(hash) || !expected[name] || name == "SHA256SUMS" || listed[name] {
			return m, nil, errors.New("invalid checksum inventory")
		}
		actual, err := fileHash(filepath.Join(dir, name))
		if err != nil || actual != hash {
			return m, nil, fmt.Errorf("checksum mismatch: %s", name)
		}
		listed[name] = true
	}
	if len(listed) != len(expected)-1 {
		return m, nil, errors.New("incomplete checksum inventory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return m, nil, err
	}
	if len(entries) != len(expected) {
		return m, nil, errors.New("unexpected publication entries")
	}
	var files []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !expected[entry.Name()] || !info.Mode().IsRegular() {
			return m, nil, errors.New("unexpected or non-regular publication entry")
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	return m, files, nil
}
