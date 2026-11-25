// Command release provides the shared local and CI build entry point.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/version"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type nativeDependency struct {
	Repository string            `json:"repository"`
	Version    string            `json:"version"`
	Commit     string            `json:"source_commit"`
	SHA256     map[string]string `json:"sha256"`
}

type dependencyLock struct {
	Schema   int              `json:"schema"`
	Go       string           `json:"go"`
	Protocol int              `json:"protocol"`
	Native   nativeDependency `json:"spidermonkey"`
	LLVM     struct {
		Version string `json:"version"`
		Archive string `json:"archive"`
		SHA256  string `json:"sha256"`
	} `json:"llvm_mingw"`
	Zig   string `json:"zig"`
	MacOS string `json:"macos_deployment_target"`
}

const productName = "aistudio-signer"

var (
	targets       = []string{"windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}
	tagPattern    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
	labelPattern  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootFiles = []string{
		".gitignore", ".gitattributes", "LICENSE", "NOTICE", "README.md", "go.mod", "go.sum",
		"config.example.json", "windows_profile.json", "windows_voices.json", "windows_webgl.json",
	}
	packageFiles = []string{"LICENSE", "NOTICE", "README.md", "config.example.json"}
)

type tool struct {
	ctx  context.Context
	root string
	lock dependencyLock
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stdout, `Usage: go run ./release <command> [options]
  build     Compile locally using an installed native library and compiler
  check     Check the committed source publication boundary
  release   Build, test, inspect and package one native platform
  assemble  Verify all platform artifacts and create the publication directory
  publish   Verify a publication directory and upload a tagged GitHub Release
Run a command with -h for its options. build never runs tests or downloads native tools.`)
}

func execute(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return nil
	}
	if args[0] == "publish" {
		fs := flag.NewFlagSet("publish", flag.ContinueOnError)
		dir := fs.String("directory", "publish", "Complete publication directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		return publish(ctx, *dir)
	}
	root, err := findRoot()
	if err != nil {
		return err
	}
	t := &tool{ctx: ctx, root: root}
	if err := readJSON(filepath.Join(root, "release", "dependencies.json"), &t.lock); err != nil {
		return err
	}
	if err := t.validateLock(); err != nil {
		return err
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "build":
		target := fs.String("target", localTarget(), "Target OS-architecture")
		library := fs.String("spidermonkey-root", os.Getenv("SPIDERMONKEY_ROOT"), "Installed native include/lib directory (required)")
		output := fs.String("output", "", "Output path; default bin/aistudio-signer[.exe]")
		ver := fs.String("version", "dev", "Informational binary version")
		commit := fs.String("commit", "unknown", "Informational source commit")
		static := fs.Bool("static-musl", false, "Link Linux with static musl and netgo/osusergo tags")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if !labelPattern.MatchString(*ver) || (*commit != "unknown" && !regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`).MatchString(*commit)) {
			return errors.New("invalid version or commit")
		}
		if err := validTarget(*target); err != nil {
			return err
		}
		if *static && !strings.HasPrefix(*target, "linux-") {
			return errors.New("-static-musl is only valid for Linux")
		}
		if *output == "" {
			*output = filepath.Join(root, "bin", executable(*target))
		}
		*output, err = filepath.Abs(*output)
		if err != nil {
			return err
		}
		env, tags, link, err := t.buildEnvironment(*target, *library, os.Environ(), *static)
		if err != nil {
			return err
		}
		return t.compile(env, tags, link, *output, *ver, *commit, false)
	case "check":
		out := fs.String("github-output", "", "Append pinned go/zig versions to this Actions output file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if err := t.checkSources(); err != nil {
			return err
		}
		if *out != "" {
			f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(f, "go=%s\nzig=%s\n", t.lock.Go, t.lock.Zig)
			return errors.Join(err, f.Close())
		}
		fmt.Println("Source publication boundary verified.")
		return nil
	case "release":
		target := fs.String("target", runtime.GOOS+"-"+runtime.GOARCH, "Native runner target")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		return t.release(*target)
	case "assemble":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		return t.assemble()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func localTarget() string {
	goos, arch := os.Getenv("GOOS"), os.Getenv("GOARCH")
	if goos == "" {
		goos = runtime.GOOS
	}
	if arch == "" {
		arch = runtime.GOARCH
	}
	return goos + "-" + arch
}

func validTarget(target string) error {
	if !slices.Contains(targets, target) {
		return fmt.Errorf("unsupported target %q", target)
	}
	return nil
}

func executable(target string) string {
	if strings.HasPrefix(target, "windows-") {
		return productName + ".exe"
	}
	return productName
}

func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "release", "dependencies.json")); err == nil && info.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run from this repository or one of its subdirectories")
		}
		dir = parent
	}
}

func readJSON(name string, value any) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one JSON value in %s", name)
	}
	return nil
}

func writeJSON(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(name, append(data, '\n'), 0644)
}

func (t *tool) validateLock() error {
	if t.lock.Schema != 1 || t.lock.Protocol < 1 || !version.IsValid("go"+t.lock.Go) || !commitPattern.MatchString(t.lock.Native.Commit) || len(t.lock.Native.SHA256) != len(targets) {
		return errors.New("invalid release/dependencies.json")
	}
	for _, target := range targets {
		if !hashPattern.MatchString(t.lock.Native.SHA256[target]) {
			return fmt.Errorf("missing native checksum for %s", target)
		}
	}
	for _, label := range []string{t.lock.Native.Version, t.lock.LLVM.Version, t.lock.Zig, t.lock.MacOS} {
		if !labelPattern.MatchString(label) {
			return errors.New("invalid pinned dependency version")
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(t.lock.Native.Repository) || filepath.Base(t.lock.LLVM.Archive) != t.lock.LLVM.Archive || !hashPattern.MatchString(t.lock.LLVM.SHA256) {
		return errors.New("invalid dependency source or checksum")
	}
	return nil
}

// run never invokes a command shell. CC/CXX command strings are interpreted by Go.
func (t *tool) run(env []string, capture bool, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(t.ctx, timeout)
	defer cancel()
	fmt.Fprintln(os.Stderr, "+", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env, cmd.Stderr = t.root, env, os.Stderr
	cmd.WaitDelay = 5 * time.Second
	var out bytes.Buffer
	if capture {
		cmd.Stdout = &out
	} else {
		cmd.Stdout = os.Stdout
	}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s: %w", name, ctx.Err())
		}
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return strings.TrimSpace(out.String()), nil
}

func (t *tool) git(args ...string) (string, error) {
	return t.run(nil, true, time.Minute, "git", args...)
}

func (t *tool) metadata() (string, string, time.Time, error) {
	commit, err := t.git("rev-parse", "HEAD")
	if err != nil {
		return "", "", time.Time{}, err
	}
	if !commitPattern.MatchString(commit) {
		return "", "", time.Time{}, errors.New("expected a Git SHA-1 commit")
	}
	stamp, err := t.git("show", "-s", "--format=%ct", "HEAD")
	if err != nil {
		return "", "", time.Time{}, err
	}
	n, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return "", "", time.Time{}, err
	}
	ver := "dev-" + commit[:12]
	if os.Getenv("GITHUB_REF_TYPE") == "tag" {
		ver = os.Getenv("GITHUB_REF_NAME")
		if !tagPattern.MatchString(ver) {
			return "", "", time.Time{}, errors.New("invalid release tag")
		}
		tagCommit, err := t.git("rev-parse", "refs/tags/"+ver+"^{commit}")
		if err != nil || tagCommit != commit {
			return "", "", time.Time{}, errors.New("release tag does not point to HEAD")
		}
	}
	return ver, commit, time.Unix(n, 0).UTC(), nil
}

func allowedSource(name string) bool {
	if slices.Contains(rootFiles, name) || (!strings.Contains(name, "/") && strings.HasSuffix(name, ".go")) {
		return true
	}
	if strings.HasPrefix(name, "waa/") || strings.HasPrefix(name, "transport/") {
		return slices.Contains([]string{".go", ".cpp", ".h", ".js", ".gz"}, filepath.Ext(name))
	}
	return name == "release/dependencies.json" || name == ".github/workflows/release.yml" ||
		(strings.HasPrefix(name, "release/") && strings.Count(name, "/") == 1 && strings.HasSuffix(name, ".go"))
}

func (t *tool) checkSources() error {
	top, err := t.git("rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	actual, err := filepath.EvalSymlinks(top)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(t.root)
	if err != nil || (actual != root && !(runtime.GOOS == "windows" && strings.EqualFold(actual, root))) {
		return errors.New("repository root must be the signer directory, not its parent")
	}
	entries, err := t.git("ls-files", "--stage", "-z")
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, entry := range strings.Split(entries, "\x00") {
		if entry == "" {
			continue
		}
		meta, name, ok := strings.Cut(entry, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 || fields[2] != "0" || (fields[0] != "100644" && fields[0] != "100755") || !allowedSource(name) {
			return fmt.Errorf("unapproved tracked entry: %q", name)
		}
		seen[name] = true
	}
	for _, name := range append(append([]string{}, packageFiles...), "go.mod", "go.sum", "release/dependencies.json", "release/main.go", ".github/workflows/release.yml") {
		if !seen[name] {
			return fmt.Errorf("required source file is not tracked: %s", name)
		}
	}
	if _, err := t.git("diff", "--quiet", "HEAD", "--"); err != nil {
		return errors.New("release builds require committed, unchanged source")
	}
	untracked, err := t.git("ls-files", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	if untracked != "" {
		return errors.New("commit or remove untracked source files before release")
	}
	mod, err := os.ReadFile(filepath.Join(t.root, "go.mod"))
	if err != nil {
		return err
	}
	match := regexp.MustCompile(`(?m)^go\s+(\S+)\s*$`).FindSubmatch(mod)
	if len(match) != 2 || version.Compare("go"+t.lock.Go, "go"+string(match[1])) < 0 {
		return errors.New("pinned Go version is older than go.mod")
	}
	return nil
}
