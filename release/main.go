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
	targets            = []string{"windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}
	tagPattern         = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
	labelPattern       = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	buildCommitPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	repositoryPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	macOSPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	packageFiles       = []string{"LICENSE", "NOTICE", "README.md", "config.example.json"}
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
  build        Compile locally using an installed native library and compiler
  check        Check build inputs and read CI toolchain settings
  test-engine  Prepare the native toolchain and run the local engine test
  release      Build, check basic startup and package one native platform
  assemble     Collect all platform artifacts and write publication checksums
  publish      Verify checksums and upload a tagged GitHub Release
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
		if !labelPattern.MatchString(*ver) || (*commit != "unknown" && !buildCommitPattern.MatchString(*commit)) {
			return errors.New("invalid version or commit")
		}
		if err := validTarget(*target); err != nil {
			return err
		}
		if *static && !strings.HasPrefix(*target, "linux-") {
			return errors.New("-static-musl is only valid for Linux")
		}
		// Local builds do not validate download settings for unrelated platforms.
		if strings.HasPrefix(*target, "darwin-") {
			if err := readJSON(filepath.Join(root, "release", "dependencies.json"), &t.lock); err != nil {
				return err
			}
			if !macOSPattern.MatchString(t.lock.MacOS) {
				return errors.New("invalid macOS deployment target")
			}
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
		out := fs.String("github-output", "", "Append CI go/zig versions to this Actions output file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if err := t.loadLock(); err != nil {
			return err
		}
		if !version.IsValid("go"+t.lock.Go) || !labelPattern.MatchString(t.lock.Zig) {
			return errors.New("invalid CI toolchain versions")
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
		fmt.Println("Required build inputs verified.")
		return nil
	case "release", "test-engine":
		target := fs.String("target", runtime.GOOS+"-"+runtime.GOARCH, "Native runner target")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if err := t.loadLock(); err != nil {
			return err
		}
		if err := t.validateTarget(*target); err != nil {
			return err
		}
		if args[0] == "test-engine" {
			return t.testEngine(*target)
		}
		return t.release(*target)
	case "assemble":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if err := t.loadLock(); err != nil {
			return err
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
		if info, err := os.Stat(filepath.Join(dir, "release", "main.go")); err == nil && info.Mode().IsRegular() {
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

func (t *tool) loadLock() error {
	if err := readJSON(filepath.Join(t.root, "release", "dependencies.json"), &t.lock); err != nil {
		return err
	}
	if t.lock.Schema != 1 || t.lock.Protocol < 1 {
		return errors.New("invalid release/dependencies.json")
	}
	return nil
}

// Each native job validates only the dependency and toolchain it will use.
func (t *tool) validateTarget(target string) error {
	if err := validTarget(target); err != nil {
		return err
	}
	if target != runtime.GOOS+"-"+runtime.GOARCH {
		return errors.New("release and engine tests require a native runner")
	}
	if !repositoryPattern.MatchString(t.lock.Native.Repository) ||
		!labelPattern.MatchString(t.lock.Native.Version) || !hashPattern.MatchString(t.lock.Native.SHA256[target]) {
		return fmt.Errorf("invalid native dependency for %s", target)
	}
	if strings.HasPrefix(target, "windows-") {
		spec := t.lock.LLVM
		if !labelPattern.MatchString(spec.Version) || !labelPattern.MatchString(spec.Archive) ||
			!strings.HasSuffix(spec.Archive, ".zip") || !hashPattern.MatchString(spec.SHA256) {
			return errors.New("invalid Windows toolchain dependency")
		}
	}
	if strings.HasPrefix(target, "darwin-") && !macOSPattern.MatchString(t.lock.MacOS) {
		return errors.New("invalid macOS deployment target")
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

func (t *tool) checkSources() error {
	for _, name := range []string{"main.go", "go.mod", "go.sum", "release/dependencies.json"} {
		info, err := os.Stat(filepath.Join(t.root, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("build input is not a regular file: %s", name)
		}
	}
	return nil
}
