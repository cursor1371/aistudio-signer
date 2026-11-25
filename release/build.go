package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func setEnv(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		if key == name || (runtime.GOOS == "windows" && strings.EqualFold(key, name)) {
			continue
		}
		out = append(out, item)
	}
	return append(out, name+"="+value)
}

func getEnv(env []string, name string) string {
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		if key == name || (runtime.GOOS == "windows" && strings.EqualFold(key, name)) {
			return value
		}
	}
	return ""
}

// CGO uses quoted.Split, not a shell: quote the entire -I/-L argument.
func quoted(value string) (string, error) {
	value = filepath.ToSlash(value)
	if strings.ContainsAny(value, "\"'\r\n\x00") {
		return "", errors.New("unsupported quote or control character in compiler path")
	}
	return `"` + value + `"`, nil
}

func (t *tool) buildEnvironment(target, library string, env []string, static bool) ([]string, []string, []string, error) {
	root, err := validateLibrary(library)
	if err != nil {
		return nil, nil, nil, err
	}
	goos, arch, _ := strings.Cut(target, "-")
	for key, value := range map[string]string{
		"CGO_ENABLED": "1", "GOOS": goos, "GOARCH": arch,
		"GOWORK": "off", "GOTOOLCHAIN": "local",
	} {
		env = setEnv(env, key, value)
	}
	cpp, err := quoted("-I" + filepath.Join(root, "include"))
	if err != nil {
		return nil, nil, nil, err
	}
	ld, err := quoted("-L" + filepath.Join(root, "lib"))
	if err != nil {
		return nil, nil, nil, err
	}
	var tags, link []string
	if goos == "darwin" {
		if getEnv(env, "CC") == "" {
			env = setEnv(env, "CC", "clang")
		}
		if getEnv(env, "CXX") == "" {
			env = setEnv(env, "CXX", "clang++")
		}
		minimum := " -mmacosx-version-min=" + t.lock.MacOS
		cpp += minimum
		ld += minimum
		env = setEnv(env, "MACOSX_DEPLOYMENT_TARGET", t.lock.MacOS)
	} else if getEnv(env, "CC") == "" || getEnv(env, "CXX") == "" {
		return nil, nil, nil, errors.New("set CC and CXX to the matching native toolchain")
	}
	if static {
		tags = []string{"-tags", "netgo,osusergo"}
		link = []string{"-linkmode", "external", "-extldflags", "-static"}
	}
	env = setEnv(env, "CGO_CPPFLAGS", cpp)
	env = setEnv(env, "CGO_LDFLAGS", ld)
	return env, tags, link, nil
}

func (t *tool) compile(env, tags, link []string, binary, ver, commit string, strip bool) error {
	if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
		return err
	}
	flags := append([]string{}, link...)
	if strip {
		flags = append(flags, "-s", "-w")
	}
	flags = append(flags, "-X=main.releaseVersion="+ver, "-X=main.releaseCommit="+commit)
	args := append([]string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false"}, tags...)
	args = append(args, "-ldflags", strings.Join(flags, " "), "-o", binary, ".")
	fmt.Fprintln(os.Stderr, "CGO_CPPFLAGS="+getEnv(env, "CGO_CPPFLAGS"))
	fmt.Fprintln(os.Stderr, "CGO_LDFLAGS="+getEnv(env, "CGO_LDFLAGS"))
	if _, err := t.run(env, false, time.Hour, "go", args...); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Built:", binary)
	return nil
}

// Native tests and release builds share the same verified dependencies and
// compiler options. Only build output and test execution differ.
func (t *tool) releaseEnvironment(target string) ([]string, []string, []string, error) {
	library, err := t.nativeLibrary(target)
	if err != nil {
		return nil, nil, nil, err
	}
	env := os.Environ()
	var cc, cxx string
	switch {
	case strings.HasPrefix(target, "windows-"):
		spec := t.lock.LLVM
		u := "https://github.com/mstorsjo/llvm-mingw/releases/download/" + spec.Version + "/" + spec.Archive
		directory, err := t.dependencyDirectory(spec.Archive, u, spec.SHA256)
		if err != nil {
			return nil, nil, nil, err
		}
		bin := filepath.Join(directory, strings.TrimSuffix(spec.Archive, ".zip"), "bin")
		cc, err = quoted(filepath.Join(bin, "x86_64-w64-mingw32-clang.exe"))
		if err != nil {
			return nil, nil, nil, err
		}
		cxx, err = quoted(filepath.Join(bin, "x86_64-w64-mingw32-clang++.exe"))
		if err != nil {
			return nil, nil, nil, err
		}
		env = setEnv(env, "PATH", bin+string(os.PathListSeparator)+getEnv(env, "PATH"))
	case strings.HasPrefix(target, "linux-"):
		zig, err := exec.LookPath("zig")
		if err != nil {
			return nil, nil, nil, err
		}
		zig, err = filepath.EvalSymlinks(zig)
		if err != nil {
			return nil, nil, nil, err
		}
		command, err := quoted(zig)
		if err != nil {
			return nil, nil, nil, err
		}
		triple := "x86_64-linux-musl"
		if target == "linux-arm64" {
			triple = "aarch64-linux-musl"
		}
		cc, cxx = command+" cc -target "+triple, command+" c++ -target "+triple
	default:
		cc, cxx = "clang", "clang++"
	}
	for key, value := range map[string]string{
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
		"CGO_CFLAGS": "-O2 -g", "CGO_CXXFLAGS": "-O2 -g", "CC": cc, "CXX": cxx,
	} {
		env = setEnv(env, key, value)
	}
	env, tags, link, err := t.buildEnvironment(target, library, env, strings.HasPrefix(target, "linux-"))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(link) == 0 {
		link = []string{"-linkmode", "external"}
	}
	return env, tags, link, nil
}

func (t *tool) testEngine(target string) error {
	env, tags, link, err := t.releaseEnvironment(target)
	if err != nil {
		return err
	}
	args := append([]string{"test", "-mod=readonly", "-trimpath"}, tags...)
	args = append(args, "-ldflags", strings.Join(link, " "), "-count=1", "-timeout=60s", "./waa/mozjs")
	_, err = t.run(env, false, 30*time.Minute, "go", args...)
	return err
}

func (t *tool) release(target string) error {
	if err := t.checkSources(); err != nil {
		return err
	}
	ver, commit, stamp, err := t.metadata()
	if err != nil {
		return err
	}
	worktree, err := t.git("status", "--porcelain", "--untracked-files=normal", "--", ".")
	if err != nil {
		return err
	}
	if worktree != "" {
		fmt.Fprintln(os.Stderr, "warning: building local changes; sourceDirty will be recorded")
	}
	dist := filepath.Join(t.root, "dist")
	if err := os.MkdirAll(dist, 0755); err != nil {
		return err
	}
	work, err := os.MkdirTemp(dist, ".build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	env, tags, link, err := t.releaseEnvironment(target)
	if err != nil {
		return err
	}
	binary := filepath.Join(work, executable(target))
	if err := t.compile(env, tags, link, binary, ver, commit, true); err != nil {
		return err
	}
	if err := t.prepareBinary(binary, target, env); err != nil {
		return err
	}
	if err := t.smoke(binary, target, ver, commit, env); err != nil {
		return err
	}
	info := releaseInfo{
		Version: ver, Commit: commit, Protocol: t.lock.Protocol,
		Target: target, Binary: executable(target), SourceDirty: worktree != "",
	}
	info.BinarySHA256, err = fileHash(binary)
	if err != nil {
		return err
	}
	stage := filepath.Join(work, "package")
	if err := os.Mkdir(stage, 0755); err != nil {
		return err
	}
	if err := copyFile(binary, filepath.Join(stage, info.Binary), 0755); err != nil {
		return err
	}
	for _, name := range packageFiles {
		source := filepath.Join(t.root, name)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := copyFile(source, filepath.Join(stage, name), 0644); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(stage, "release-info.json"), info); err != nil {
		return err
	}

	name := productName + "-" + ver + "-" + target
	archive := filepath.Join(work, name+".zip")
	if err := zipTree(stage, archive, stamp); err != nil {
		return err
	}
	// Verify package content once, before producing the transferable report.
	if err := verifyArchive(archive, info); err != nil {
		return err
	}
	digest, err := fileHash(archive)
	if err != nil {
		return err
	}
	stat, err := os.Stat(archive)
	if err != nil {
		return err
	}
	report := platformReport{
		Version: ver, Commit: commit, Protocol: t.lock.Protocol,
		SourceDirty: info.SourceDirty,
		Artifact:    artifact{Target: target, Name: name + ".zip", SHA256: digest, Size: stat.Size()},
	}
	// The ZIP is verified before replacing the old file on the same filesystem.
	if err := os.Rename(archive, filepath.Join(dist, report.Artifact.Name)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dist, name+".json"), report); err != nil {
		return err
	}
	fmt.Println("Release artifact:", filepath.Join(dist, report.Artifact.Name))
	return nil
}
