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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Check the target architecture, then perform required platform preparation.
// No dependency inventory or OS-library name allowlist is involved.
func (t *tool) prepareBinary(binary, target string, env []string) error {
	switch {
	case strings.HasPrefix(target, "linux-"):
		f, err := elf.Open(binary)
		if err != nil {
			return err
		}
		defer f.Close()
		machine := elf.EM_X86_64
		if target == "linux-arm64" {
			machine = elf.EM_AARCH64
		}
		if f.Machine != machine || f.Class != elf.ELFCLASS64 {
			return errors.New("wrong ELF architecture")
		}
		// Linux releases promise a static musl binary, not a host-specific loader.
		for _, program := range f.Progs {
			if program.Type == elf.PT_INTERP {
				return errors.New("static Linux release contains a dynamic interpreter")
			}
		}
		needed, err := f.DynValue(elf.DT_NEEDED)
		if err != nil {
			return err
		}
		if len(needed) != 0 {
			return errors.New("static Linux release contains shared-library dependencies")
		}
	case strings.HasPrefix(target, "darwin-"):
		f, err := macho.Open(binary)
		if err != nil {
			return err
		}
		cpu := macho.CpuAmd64
		if target == "darwin-arm64" {
			cpu = macho.CpuArm64
		}
		wrongCPU := f.Cpu != cpu
		f.Close()
		if wrongCPU {
			return errors.New("wrong Mach-O architecture")
		}
		if _, err := t.run(env, false, time.Minute, "codesign", "--force", "--sign", "-", binary); err != nil {
			return err
		}
		if _, err := t.run(env, false, time.Minute, "codesign", "--verify", binary); err != nil {
			return err
		}
	case target == "windows-amd64":
		f, err := pe.Open(binary)
		if err != nil {
			return err
		}
		defer f.Close()
		if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
			return errors.New("wrong PE architecture")
		}
	default:
		return errors.New("unsupported binary format")
	}
	return nil
}

// Basic package check only: version, hello and clean shutdown. It deliberately
// does not initialize WAA, load an account or issue model/control requests.
func (t *tool) smoke(binary, target, ver, commit string, env []string) error {
	text, err := t.run(env, true, 20*time.Second, binary, "--version", "--log-level", "error")
	if err != nil {
		return err
	}
	var metadata struct {
		Component string `json:"component"`
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		Protocol  int    `json:"protocol"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
	}
	if err := json.Unmarshal([]byte(text), &metadata); err != nil {
		return err
	}
	goos, arch, _ := strings.Cut(target, "-")
	if metadata.Component != productName || metadata.Version != ver || metadata.Commit != commit ||
		metadata.Protocol != t.lock.Protocol || metadata.OS != goos || metadata.Arch != arch {
		return errors.New("binary metadata does not match this build")
	}

	dir, err := os.MkdirTemp("", "signer-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	config := filepath.Join(dir, "config.json")
	if err := writeJSON(config, map[string]any{
		"storage_state": "absent/state.json", "model": "gemini-4-hydrogen",
	}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config", config, "--log-level", "error", "--log-format", "json")
	cmd.Dir, cmd.Env, cmd.Stderr = dir, env, os.Stderr
	cmd.WaitDelay = 5 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer out.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read IPC hello: %w", err)
		}
		return errors.New("process exited before IPC hello")
	}
	var hello struct {
		Type string `json:"type"`
		Data struct {
			Protocol int `json:"protocol"`
		} `json:"data"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &hello); err != nil {
		return fmt.Errorf("invalid IPC hello: %w", err)
	}
	if hello.Type != "hello" || hello.Data.Protocol != t.lock.Protocol {
		return errors.New("invalid IPC hello")
	}
	if err := json.NewEncoder(in).Encode(map[string]string{"op": "shutdown"}); err != nil {
		return err
	}
	if scanner.Scan() {
		return errors.New("unexpected IPC output after shutdown")
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	err = cmd.Wait()
	waited = true
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("IPC shutdown: %w", err)
	}
	return nil
}
