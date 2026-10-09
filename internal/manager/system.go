package manager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner executes external commands. Splitting reads from writes is what
// makes --dry-run safe: reads still run so the preview is accurate, writes
// are only printed.
type Runner interface {
	// Output runs a read-only command and returns its stdout.
	Output(name string, args ...string) ([]byte, error)
	// Run runs a command that changes system state.
	Run(name string, args ...string) error
}

// ExecRunner runs real commands.
type ExecRunner struct {
	DryRun bool
	Log    io.Writer
}

func (r ExecRunner) Output(name string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (r ExecRunner) Run(name string, args ...string) error {
	if r.DryRun {
		fmt.Fprintf(r.Log, "  [dry-run] %s %s\n", name, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = r.Log, r.Log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// LookupPublicIP asks a public echo service for this host's IPv4 address.
func LookupPublicIP() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		// Never trust the response blindly: it ends up in client configs.
		if a, err := netip.ParseAddr(strings.TrimSpace(string(body))); err == nil && a.Is4() {
			return a.String(), nil
		}
	}
	return "", errors.New("could not detect the public IP; pass --endpoint")
}

// writeFileAtomic writes data to path with the given mode via a temp file and
// rename, so a crash or full disk never leaves a half-written wg0.conf.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
