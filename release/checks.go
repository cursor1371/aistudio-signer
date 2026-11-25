package main

import (
	"bufio"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type linkage struct {
	Linkage             string   `json:"linkage"`
	DynamicDependencies []string `json:"dynamicDependencies"`
	MinimumOS           string   `json:"minimumOS,omitempty"`
	Signature           string   `json:"signature,omitempty"`
}

type buildInfo struct {
	Component        string           `json:"component"`
	Version          string           `json:"version"`
	Commit           string           `json:"commit"`
	Protocol         int              `json:"protocol"`
	GoVersion        string           `json:"goVersion"`
	OS               string           `json:"os"`
	Arch             string           `json:"arch"`
	Target           string           `json:"target"`
	Compiler         string           `json:"compiler"`
	Binary           string           `json:"binary"`
	BinarySHA256     string           `json:"binarySHA256"`
	SourceRepository string           `json:"sourceRepository"`
	SpiderMonkey     nativeDependency `json:"spidermonkey"`
	Dependencies     linkage          `json:"dependencies"`
	GoModules        int              `json:"goModules"`
	Checks           []string         `json:"checks"`
}

func (t *tool) inspectBinary(binary, target, toolRoot string, env []string) (linkage, error) {
	report := linkage{DynamicDependencies: []string{}}
	switch {
	case strings.HasPrefix(target, "linux-"):
		f, err := elf.Open(binary)
		if err != nil {
			return report, err
		}
		defer f.Close()
		machine := elf.EM_X86_64
		if target == "linux-arm64" {
			machine = elf.EM_AARCH64
		}
		if f.Machine != machine || f.Class != elf.ELFCLASS64 {
			return report, errors.New("wrong ELF architecture")
		}
		for _, prog := range f.Progs {
			if prog.Type == elf.PT_INTERP {
				return report, errors.New("Linux release must not require a dynamic interpreter")
			}
		}
		deps, err := f.ImportedLibraries()
		if err != nil || len(deps) != 0 {
			return report, errors.New("Linux release must not import dynamic libraries")
		}
		report.Linkage = "static-musl"
	case strings.HasPrefix(target, "darwin-"):
		f, err := macho.Open(binary)
		if err != nil {
			return report, err
		}
		cpu := macho.CpuAmd64
		if target == "darwin-arm64" {
			cpu = macho.CpuArm64
		}
		deps, readErr := f.ImportedLibraries()
		wrongCPU := f.Cpu != cpu
		f.Close()
		if readErr != nil || wrongCPU {
			return report, errors.New("invalid Mach-O architecture or import table")
		}
		for _, name := range deps {
			if !strings.HasPrefix(name, "/usr/lib/") && !strings.HasPrefix(name, "/System/Library/") {
				return report, fmt.Errorf("non-system Mach-O dependency: %s", name)
			}
		}
		if _, err := t.run(env, false, time.Minute, "codesign", "--force", "--sign", "-", binary); err != nil {
			return report, err
		}
		if _, err := t.run(env, false, time.Minute, "codesign", "--verify", "--strict", binary); err != nil {
			return report, err
		}
		report.Linkage, report.MinimumOS = "system-libraries", t.lock.MacOS
		report.Signature = "ad-hoc; not Developer ID signed or notarized"
		report.DynamicDependencies = append(report.DynamicDependencies, deps...)
	case target == "windows-amd64":
		f, err := pe.Open(binary)
		if err != nil {
			return report, err
		}
		defer f.Close()
		if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
			return report, errors.New("wrong PE architecture")
		}
		// debug/pe.ImportedLibraries is not implemented in the supported Go
		// toolchain. Use the pinned compiler's inspector, not a PATH lookup.
		output, err := t.run(env, true, time.Minute, filepath.Join(toolRoot, "bin", "llvm-readobj.exe"), "--coff-imports", binary)
		if err != nil {
			return report, err
		}
		matches := regexp.MustCompile(`(?i)Name:\s+(\S+\.dll)`).FindAllStringSubmatch(output, -1)
		if len(matches) == 0 {
			return report, errors.New("invalid PE import table")
		}
		deps := make([]string, 0, len(matches))
		for _, match := range matches {
			deps = append(deps, match[1])
		}
		system := strings.Fields("kernel32.dll ntdll.dll user32.dll advapi32.dll bcrypt.dll crypt32.dll ws2_32.dll winmm.dll psapi.dll dbghelp.dll userenv.dll shell32.dll ole32.dll oleaut32.dll rpcrt4.dll shlwapi.dll secur32.dll wintrust.dll kernelbase.dll powrprof.dll imm32.dll gdi32.dll setupapi.dll version.dll cfgmgr32.dll normaliz.dll mswsock.dll iphlpapi.dll dnsapi.dll ucrtbase.dll msvcrt.dll winhttp.dll")
		for _, name := range deps {
			lower := strings.ToLower(name)
			allowed := strings.HasPrefix(lower, "api-ms-win-") || strings.HasPrefix(lower, "ext-ms-win-")
			for _, item := range system {
				allowed = allowed || lower == item
			}
			if !allowed {
				return report, fmt.Errorf("non-system PE dependency: %s", name)
			}
		}
		report.Linkage, report.Signature = "system-libraries", "unsigned"
		report.DynamicDependencies = append(report.DynamicDependencies, deps...)
	default:
		return report, errors.New("unsupported binary format")
	}
	sort.Strings(report.DynamicDependencies)
	return report, nil
}

type ipcMessage struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Data     json.RawMessage `json:"data"`
	Reusable *bool           `json:"reusable"`
	Error    *struct {
		Code string `json:"code"`
	} `json:"error"`
}

type ipcRead struct {
	message ipcMessage
	err     error
}

func (t *tool) smoke(binary, target, ver, commit string, env []string) (buildInfo, error) {
	var metadata buildInfo
	text, err := t.run(env, true, 20*time.Second, binary, "--version")
	if err != nil {
		return metadata, err
	}
	if err := json.Unmarshal([]byte(text), &metadata); err != nil {
		return metadata, err
	}
	goos, arch, _ := strings.Cut(target, "-")
	if metadata.Component != productName || metadata.Version != ver || metadata.Commit != commit || metadata.Protocol != t.lock.Protocol || metadata.OS != goos || metadata.Arch != arch || metadata.GoVersion != "go"+t.lock.Go {
		return metadata, errors.New("binary metadata does not match this build")
	}
	if _, err := t.run(env, true, 20*time.Second, binary, "--help"); err != nil {
		return metadata, err
	}
	dir, err := os.MkdirTemp("", "signer-smoke-")
	if err != nil {
		return metadata, err
	}
	defer os.RemoveAll(dir)
	config := filepath.Join(dir, "config.json")
	if err := writeJSON(config, map[string]any{"storage_state": "absent/state.json", "model": "gemini-4-hydrogen", "capacity": 2}); err != nil {
		return metadata, err
	}
	// No init is sent. The absent state path prevents accidental account use.
	ctx, cancel := context.WithTimeout(t.ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config", config, "--log-level", "error", "--log-format", "json")
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = 5 * time.Second
	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		return metadata, err
	}
	defer stderr.Close()
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return metadata, err
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return metadata, err
	}
	defer out.Close()
	if err := cmd.Start(); err != nil {
		return metadata, err
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	messages := make(chan ipcRead, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			var m ipcMessage
			err := json.Unmarshal(scanner.Bytes(), &m)
			select {
			case messages <- ipcRead{message: m, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
		err := scanner.Err()
		if err == nil {
			err = io.EOF
		}
		select {
		case messages <- ipcRead{err: err}:
		case <-ctx.Done():
		}
	}()
	receive := func() (ipcMessage, error) {
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		select {
		case item := <-messages:
			return item.message, item.err
		case <-ctx.Done():
			return ipcMessage{}, ctx.Err()
		case <-timer.C:
			return ipcMessage{}, errors.New("IPC smoke response timed out")
		}
	}
	encoder := json.NewEncoder(in)
	hello, err := receive()
	var greeting struct {
		Protocol int `json:"protocol"`
		Capacity int `json:"capacity"`
	}
	if err != nil || hello.Type != "hello" || json.Unmarshal(hello.Data, &greeting) != nil || greeting.Protocol != t.lock.Protocol || greeting.Capacity != 2 {
		return metadata, errors.New("invalid IPC hello")
	}
	if err := encoder.Encode(map[string]string{"id": "status", "op": "status"}); err != nil {
		return metadata, err
	}
	m, err := receive()
	var state struct {
		Phase string `json:"phase"`
	}
	if err != nil || m.ID != "status" || m.Type != "result" || m.Reusable == nil || !*m.Reusable || json.Unmarshal(m.Data, &state) != nil || state.Phase != "not_initialized" {
		return metadata, errors.New("invalid pre-init status")
	}
	if err := encoder.Encode(map[string]any{"id": "request", "op": "request", "params": map[string]any{}}); err != nil {
		return metadata, err
	}
	m, err = receive()
	if err != nil || m.ID != "request" || m.Type != "error" || m.Reusable == nil || !*m.Reusable || m.Error == nil || m.Error.Code != "NOT_INITIALIZED" {
		return metadata, errors.New("uninitialized request was not rejected locally")
	}
	if err := encoder.Encode(map[string]string{"op": "shutdown"}); err != nil {
		return metadata, err
	}
	if _, err := receive(); err != io.EOF {
		return metadata, errors.New("unexpected output or timeout after shutdown")
	}
	<-readerDone
	err = cmd.Wait()
	waited = true
	if err != nil {
		return metadata, fmt.Errorf("IPC shutdown: %w", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		return metadata, errors.New("pre-init check touched account state")
	}
	return metadata, nil
}

var licenseName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|copyright|notice|patents)([._-].*)?$`)

func copyLicenses(source, destination string) ([]string, error) {
	var copied []string
	err := filepath.WalkDir(source, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !licenseName.MatchString(entry.Name()) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		if err := copyFile(name, filepath.Join(destination, rel), 0644); err != nil {
			return err
		}
		copied = append(copied, filepath.ToSlash(rel))
		return nil
	})
	return copied, err
}

type module struct {
	Path    string
	Version string
	Dir     string
	Sum     string
	Main    bool
	Replace *module
}

type licenseEntry struct {
	Module   string   `json:"module"`
	Version  string   `json:"version"`
	Sum      string   `json:"sum,omitempty"`
	Licenses []string `json:"licenses"`
}

func (t *tool) collectLicenses(stage, toolRoot string, env, tags []string) (int, error) {
	licenses := filepath.Join(stage, "licenses")
	args := append([]string{"list", "-mod=readonly", "-deps", "-json"}, tags...)
	args = append(args, ".")
	text, err := t.run(env, true, 10*time.Minute, "go", args...)
	if err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	modules := make(map[string]module)
	for {
		var pkg struct {
			Module *module
		}
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if pkg.Module != nil && !pkg.Module.Main {
			modules[pkg.Module.Path] = *pkg.Module
		}
	}
	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	inventory := make([]licenseEntry, 0, len(keys))
	for _, key := range keys {
		m := modules[key]
		if m.Replace != nil || m.Dir == "" || m.Version == "" {
			return 0, fmt.Errorf("module source unavailable or replaced: %s", key)
		}
		rel := "go/" + m.Path + "@" + m.Version
		dest, err := safeArchivePath(licenses, rel)
		if err != nil {
			return 0, err
		}
		files, err := copyLicenses(m.Dir, dest)
		if err != nil {
			return 0, err
		}
		if len(files) == 0 {
			return 0, fmt.Errorf("no license found for %s", key)
		}
		for i := range files {
			files[i] = rel + "/" + files[i]
		}
		inventory = append(inventory, licenseEntry{m.Path, m.Version, m.Sum, files})
	}
	goRoot, err := t.run(env, true, time.Minute, "go", "env", "GOROOT")
	if err != nil {
		return 0, err
	}
	for _, name := range []string{"LICENSE", "PATENTS"} {
		if err := copyFile(filepath.Join(goRoot, name), filepath.Join(licenses, "go-toolchain", name), 0644); err != nil {
			return 0, err
		}
	}
	spec := t.lock.Native
	base := "https://raw.githubusercontent.com/" + spec.Repository + "/" + spec.Commit
	for _, item := range []struct{ remote, local string }{{"LICENSE", "LICENSE"}, {"toolkit/content/license.html", "license.html"}} {
		if err := download(t.ctx, base+"/"+item.remote, filepath.Join(licenses, "spidermonkey", item.local), ""); err != nil {
			return 0, err
		}
	}
	source := fmt.Sprintf("Source revision: https://github.com/%s/tree/%s\nSource archive: https://github.com/%s/archive/%s.tar.gz\nNative libraries: https://github.com/%s/releases/tag/%s\nThe native libraries are used without local patches. Preserve access to their corresponding source when redistributing.\n", spec.Repository, spec.Commit, spec.Repository, spec.Commit, spec.Repository, spec.Version)
	if err := os.WriteFile(filepath.Join(licenses, "spidermonkey", "SOURCE.txt"), []byte(source), 0644); err != nil {
		return 0, err
	}
	if toolRoot != "" {
		files, err := copyLicenses(toolRoot, filepath.Join(licenses, "native-toolchain"))
		if err != nil {
			return 0, err
		}
		if len(files) == 0 {
			return 0, errors.New("native toolchain licenses were not found")
		}
	}
	return len(inventory), writeJSON(filepath.Join(licenses, "go-modules.json"), inventory)
}
