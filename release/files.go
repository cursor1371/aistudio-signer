package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func fileHash(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(source, destination string, mode fs.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}

func httpsClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.User != nil || len(via) >= 10 {
				return errors.New("refusing unsafe or excessive redirect")
			}
			return nil
		},
	}
}

func download(ctx context.Context, rawURL, destination, expected string) error {
	if !strings.HasPrefix(rawURL, "https://") {
		return errors.New("downloads require HTTPS")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	client := httpsClient(15 * time.Minute)
	defer client.CloseIdleConnections()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		fmt.Fprintln(os.Stderr, "download:", filepath.Base(destination))
		retry, err := downloadOnce(ctx, client, rawURL, destination, expected)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			break
		}
	}
	return fmt.Errorf("download %s: %w", filepath.Base(destination), last)
}

func downloadOnce(ctx context.Context, client *http.Client, rawURL, destination, expected string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "aistudio-signer-release")
	response, err := client.Do(req)
	if err != nil {
		return true, errors.New("HTTPS request failed") // Do not expose proxy credentials or signed redirect URLs.
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode == 429 || response.StatusCode >= 500, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".download-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	const limit = int64(3 << 30)
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(response.Body, limit+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return true, err
	}
	if n > limit {
		return false, errors.New("download exceeds size limit")
	}
	if expected != "" && hex.EncodeToString(h.Sum(nil)) != expected {
		return false, errors.New("SHA-256 mismatch")
	}
	if err := os.Rename(f.Name(), destination); err != nil {
		return false, err
	}
	return false, nil
}

func safeArchivePath(root, name string) (string, error) {
	// Reject traversal before cleaning so an archive cannot hide it in a/../b.
	if strings.ContainsAny(name, "\\:\x00\r\n") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("unsafe archive path %q", name)
		}
	}
	clean := filepath.FromSlash(path.Clean(name))
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return filepath.Join(root, clean), nil
}

func unpack(archive, destination string) error {
	if err := os.Mkdir(destination, 0755); err != nil {
		return err
	}
	var total int64
	write := func(name string, directory bool, mode fs.FileMode, size int64, source io.Reader) error {
		dest, err := safeArchivePath(destination, name)
		if err != nil {
			return err
		}
		if directory {
			return os.MkdirAll(dest, 0755)
		}
		if size < 0 || size > 2<<30 || total+size > 8<<30 {
			return errors.New("native archive exceeds extraction limits")
		}
		total += size
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		permissions := fs.FileMode(0644)
		if mode&0111 != 0 {
			permissions = 0755
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, permissions)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(source, size+1))
		err = errors.Join(err, f.Close())
		if err == nil && n != size {
			err = errors.New("archive entry size mismatch")
		}
		return err
	}
	if strings.HasSuffix(archive, ".zip") {
		bundle, err := zip.OpenReader(archive)
		if err != nil {
			return err
		}
		defer bundle.Close()
		for _, entry := range bundle.File {
			if !entry.Mode().IsRegular() && !entry.FileInfo().IsDir() {
				return errors.New("native ZIP may not contain symlinks or special files")
			}
			if entry.UncompressedSize64 > 2<<30 {
				return errors.New("native ZIP entry too large")
			}
			r, err := entry.Open()
			if err != nil {
				return err
			}
			err = write(entry.Name, entry.FileInfo().IsDir(), entry.Mode(), int64(entry.UncompressedSize64), r)
			err = errors.Join(err, r.Close())
			if err != nil {
				return err
			}
		}
		return nil
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			_, err = io.Copy(io.Discard, gz) // Verify the gzip trailer as well.
			return err
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return errors.New("native TAR may only contain regular files and directories")
		}
		if err := write(header.Name, header.Typeflag == tar.TypeDir, header.FileInfo().Mode(), header.Size, tr); err != nil {
			return err
		}
	}
}

func zipTree(source, destination string, stamp time.Time) error {
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	z := zip.NewWriter(out)
	if stamp.Before(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)) {
		stamp = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	err = filepath.WalkDir(source, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular package entry: %s", name)
		}
		rel, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		header := &zip.FileHeader{Name: rel, Method: zip.Deflate, Modified: stamp.UTC()}
		header.SetMode(0644)
		if rel == productName || rel == productName+".exe" {
			header.SetMode(0755)
		}
		writer, err := z.CreateHeader(header)
		if err != nil {
			return err
		}
		in, err := os.Open(name)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, in)
		return errors.Join(err, in.Close())
	})
	err = errors.Join(err, z.Close(), out.Close())
	ok = err == nil
	return err
}

func validateLibrary(root string) (string, error) {
	if root == "" {
		return "", errors.New("-spidermonkey-root or SPIDERMONKEY_ROOT is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	for _, name := range []string{"include/jsapi.h", "include/js/RealmOptions.h", "lib/libjs_static.a", "lib/libjsrust.a"} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("missing native file: %s", filepath.Join(root, name))
		}
	}
	return root, nil
}

func (t *tool) nativeLibrary(target, work string) (string, error) {
	spec := t.lock.Native
	name := "spidermonkey-" + spec.Version + "-" + target + ".tar.gz"
	archive := filepath.Join(work, name)
	u := "https://github.com/" + spec.Repository + "/releases/download/" + spec.Version + "/" + name
	if err := download(t.ctx, u, archive, spec.SHA256[target]); err != nil {
		return "", err
	}
	root := filepath.Join(work, "spidermonkey")
	if err := unpack(archive, root); err != nil {
		return "", err
	}
	return validateLibrary(root)
}
