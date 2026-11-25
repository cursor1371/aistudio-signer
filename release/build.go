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
	parts := strings.Split(target, "-")
	for key, value := range map[string]string{
		"CGO_ENABLED": "1", "GOOS": parts[0], "GOARCH": parts[1],
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
	if parts[0] == "darwin" {
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

func (t *tool) releaseEnvironment(target, library, work string) ([]string, []string, []string, string, string, error) {
	// Start with local build options, but release builds select the compiler and
	// reset code-generation flags rather than inheriting developer overrides.
	env := os.Environ()
	var toolRoot, cc, cxx, compiler string
	switch {
	case strings.HasPrefix(target, "windows-"):
		spec := t.lock.LLVM
		archive := filepath.Join(work, spec.Archive)
		u := "https://github.com/mstorsjo/llvm-mingw/releases/download/" + spec.Version + "/" + spec.Archive
		if err := download(t.ctx, u, archive, spec.SHA256); err != nil {
			return nil, nil, nil, "", "", err
		}
		dest := filepath.Join(work, "toolchain")
		if err := unpack(archive, dest); err != nil {
			return nil, nil, nil, "", "", err
		}
		toolRoot = filepath.Join(dest, strings.TrimSuffix(spec.Archive, ".zip"))
		var err error
		cc, err = quoted(filepath.Join(toolRoot, "bin", "x86_64-w64-mingw32-clang.exe"))
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		cxx, err = quoted(filepath.Join(toolRoot, "bin", "x86_64-w64-mingw32-clang++.exe"))
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		env = setEnv(env, "PATH", filepath.Join(toolRoot, "bin")+string(os.PathListSeparator)+getEnv(env, "PATH"))
		compiler = "llvm-mingw-" + spec.Version
	case strings.HasPrefix(target, "linux-"):
		zig, err := exec.LookPath("zig")
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		zig, err = filepath.EvalSymlinks(zig)
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		v, err := t.run(env, true, time.Minute, zig, "version")
		if err != nil || v != t.lock.Zig {
			return nil, nil, nil, "", "", errors.New("unexpected Zig version")
		}
		toolRoot = filepath.Dir(zig)
		command, err := quoted(zig)
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		triple := "x86_64-linux-musl"
		if target == "linux-arm64" {
			triple = "aarch64-linux-musl"
		}
		cc, cxx = command+" cc -target "+triple, command+" c++ -target "+triple
		compiler = "zig-" + t.lock.Zig
	default:
		cc, cxx = "clang", "clang++"
		v, err := t.run(env, true, time.Minute, cc, "--version")
		if err != nil {
			return nil, nil, nil, "", "", err
		}
		compiler = strings.Split(v, "\n")[0]
	}
	// The local and release commands share buildEnvironment and compile.
	// Supply explicit compiler values without mutating the parent environment.
	for key, value := range map[string]string{
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
		"CGO_CFLAGS": "-O2 -g", "CGO_CXXFLAGS": "-O2 -g", "CC": cc, "CXX": cxx,
	} {
		env = setEnv(env, key, value)
	}
	base, tags, link, err := t.buildEnvironment(target, library, env, strings.HasPrefix(target, "linux-"))
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	if len(link) == 0 {
		link = []string{"-linkmode", "external"}
	}
	v, err := t.run(base, true, time.Minute, "go", "env", "GOVERSION")
	if err != nil || v != "go"+t.lock.Go {
		return nil, nil, nil, "", "", errors.New("release requires Go " + t.lock.Go)
	}
	return base, tags, link, toolRoot, compiler, nil
}

func (t *tool) release(target string) error {
	if err := validTarget(target); err != nil {
		return err
	}
	if target != runtime.GOOS+"-"+runtime.GOARCH {
		return errors.New("release requires a native runner for build and smoke checks")
	}
	if err := t.checkSources(); err != nil {
		return err
	}
	ver, commit, stamp, err := t.metadata()
	if err != nil {
		return err
	}
	dist := filepath.Join(t.root, "dist")
	if err := os.MkdirAll(dist, 0755); err != nil {
		return err
	}
	name := productName + "-" + ver + "-" + target
	archive, report := filepath.Join(dist, name+".zip"), filepath.Join(dist, name+".json")
	for _, item := range []string{archive, report} {
		if _, err := os.Lstat(item); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("output exists or cannot be inspected: %s", item)
		}
	}
	work, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "signer-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	library, err := t.nativeLibrary(target, work)
	if err != nil {
		return err
	}
	env, tags, link, toolRoot, compiler, err := t.releaseEnvironment(target, library, work)
	if err != nil {
		return err
	}
	for _, args := range [][]string{{"mod", "download"}, {"mod", "verify"}} {
		if _, err := t.run(env, false, 20*time.Minute, "go", args...); err != nil {
			return err
		}
	}
	binary := filepath.Join(work, executable(target))
	if err := t.compile(env, tags, link, binary, ver, commit, true); err != nil {
		return err
	}
	testArgs := append([]string{"test", "-mod=readonly", "-trimpath"}, tags...)
	testArgs = append(testArgs, "-ldflags", strings.Join(link, " "), "-count=1", "-timeout=60s", "./waa/mozjs")
	if _, err := t.run(env, false, 30*time.Minute, "go", testArgs...); err != nil {
		return err
	}
	deps, err := t.inspectBinary(binary, target, toolRoot, env)
	if err != nil {
		return err
	}
	metadata, err := t.smoke(binary, target, ver, commit, env)
	if err != nil {
		return err
	}
	stage := filepath.Join(work, "package")
	if err := os.Mkdir(stage, 0755); err != nil {
		return err
	}
	if err := copyFile(binary, filepath.Join(stage, executable(target)), 0755); err != nil {
		return err
	}
	for _, file := range packageFiles {
		if err := copyFile(filepath.Join(t.root, file), filepath.Join(stage, file), 0644); err != nil {
			return err
		}
	}
	modules, err := t.collectLicenses(stage, toolRoot, env, tags)
	if err != nil {
		return err
	}
	if err := t.checkSources(); err != nil {
		return err
	}
	metadata.Target, metadata.Compiler, metadata.Binary = target, compiler, executable(target)
	metadata.BinarySHA256, err = fileHash(binary)
	if err != nil {
		return err
	}
	metadata.SourceRepository = os.Getenv("GITHUB_REPOSITORY")
	metadata.SpiderMonkey, metadata.Dependencies = t.lock.Native, deps
	metadata.GoModules = modules
	metadata.Checks = []string{"native-engine", "version", "help", "ipc-no-init", "linkage"}
	if err := writeJSON(filepath.Join(stage, "release-info.json"), metadata); err != nil {
		return err
	}
	if err := zipTree(stage, archive, stamp); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.Remove(archive)
			os.Remove(report)
		}
	}()
	hash, err := fileHash(archive)
	if err != nil {
		return err
	}
	info, err := os.Stat(archive)
	if err != nil {
		return err
	}
	if err := writeJSON(report, artifact{Target: target, Name: name+".zip", SHA256: hash, Size: info.Size(), Build: metadata}); err != nil {
		return err
	}
	complete = true
	fmt.Println("Release artifact:", archive)
	return nil
}
