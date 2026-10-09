package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end through the CLI with fake system binaries on PATH, the same
// approach the Bash test suite uses.
func setup(t *testing.T) (dir string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0o755)
	fakes := map[string]string{
		"wg":        "#!/bin/sh\n[ \"$1\" = show ] && exit 1\nexit 0\n", // interface down
		"wg-quick":  "#!/bin/sh\nexit 0\n",
		"ip":        "#!/bin/sh\necho 'default via 10.0.0.1 dev eth0'\n",
		"sysctl":    "#!/bin/sh\nexit 0\n",
		"systemctl": "#!/bin/sh\nexit 0\n",
	}
	for name, body := range fakes {
		os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SYSCTL_CONF", filepath.Join(root, "sysctl.conf"))
	return filepath.Join(root, "wireguard")
}

func wgm(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var o, e bytes.Buffer
	err = run(args, &o, &e)
	return o.String(), e.String(), err
}

func TestCLIWorkflow(t *testing.T) {
	dir := setup(t)
	if _, e, err := wgm(t, "init", "--dir", dir, "--endpoint", "vpn.example.com"); err != nil {
		t.Fatalf("init: %v\n%s", err, e)
	}

	// Flags after the positional argument work too.
	out, e, err := wgm(t, "add", "laptop", "--dir", dir)
	if err != nil {
		t.Fatalf("add: %v\n%s", err, e)
	}
	if !strings.HasPrefix(out, "[Interface]") || !strings.Contains(out, "Endpoint = vpn.example.com:51820") {
		t.Fatalf("stdout should be exactly the client config, got:\n%s", out)
	}
	if strings.Contains(out, "Added") {
		t.Fatal("status message leaked into stdout")
	}

	shown, _, _ := wgm(t, "show", "--dir", dir, "laptop")
	if shown != out {
		t.Fatal("show differs from add output")
	}

	list, _, err := wgm(t, "ls", "--dir", dir)
	if err != nil || !strings.Contains(list, "laptop") || !strings.Contains(list, "10.8.0.2") || !strings.Contains(list, "offline") {
		t.Fatalf("list: %v\n%s", err, list)
	}
	js, _, _ := wgm(t, "list", "--json", "--dir", dir)
	if !strings.Contains(js, `"name": "laptop"`) {
		t.Fatalf("json: %s", js)
	}

	if _, _, err := wgm(t, "rm", "laptop", "--dir", dir); err != nil {
		t.Fatal(err)
	}
	list, _, _ = wgm(t, "list", "--dir", dir)
	if !strings.Contains(list, "No clients yet") {
		t.Fatalf("after revoke: %s", list)
	}
}

func TestCLIErrors(t *testing.T) {
	dir := setup(t)
	cases := [][]string{
		{},
		{"bogus"},
		{"add", "--dir", dir},           // missing name
		{"add", "a", "b", "--dir", dir}, // extra arg
		{"add", "laptop", "--dir", dir}, // not initialized
		{"init", "--dir", dir, "--address", "nonsense"},
	}
	for _, c := range cases {
		if _, _, err := wgm(t, c...); err == nil {
			t.Errorf("wgm %v succeeded", c)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
