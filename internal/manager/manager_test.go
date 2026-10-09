package manager

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yorick1125/self-hosted-vpn/internal/wgconf"
	"github.com/yorick1125/self-hosted-vpn/internal/wgkey"
)

// fakeRunner records commands instead of running them.
type fakeRunner struct {
	mu      sync.Mutex
	ran     []string
	up      bool   // whether `wg show` succeeds
	dump    string // output of `wg show <iface> dump`
	route   string // output of `ip -4 route show default`
	confDir string
}

func (f *fakeRunner) Output(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case cmd == "ip -4 route show default":
		return []byte(f.route), nil
	case strings.HasPrefix(cmd, "wg show") && strings.HasSuffix(cmd, " dump"):
		if !f.up {
			return nil, errors.New("down")
		}
		return []byte(f.dump), nil
	case strings.HasPrefix(cmd, "wg show"):
		if !f.up {
			return nil, errors.New("down")
		}
		return nil, nil
	case strings.HasPrefix(cmd, "wg-quick strip"):
		return os.ReadFile(args[1])
	}
	return nil, errors.New("unexpected command: " + cmd)
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, name+" "+strings.Join(args, " "))
	return nil
}

func newTestManager(t *testing.T) (*Manager, *fakeRunner, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	r := &fakeRunner{route: "default via 172.31.0.1 dev ens5 proto dhcp\n", confDir: dir}
	out := &bytes.Buffer{}
	m := &Manager{
		Dir: filepath.Join(dir, "wireguard"), Iface: "wg0",
		SysctlPath: filepath.Join(dir, "sysctl.d", "99-wireguard.conf"),
		Runner:     r, Out: out,
		LookupPublicIP: func() (string, error) { return "203.0.113.7", nil },
	}
	return m, r, out
}

func initServer(t *testing.T, m *Manager) {
	t.Helper()
	err := m.Init(InitOptions{Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820})
	if err != nil {
		t.Fatal(err)
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestInitWritesLockedDownServer(t *testing.T) {
	m, r, _ := newTestManager(t)
	initServer(t, m)

	conf, _ := os.ReadFile(m.confPath())
	iface, err := wgconf.ParseInterface(string(conf))
	if err != nil {
		t.Fatal(err)
	}
	if iface.Address.String() != "10.8.0.1/24" || iface.ListenPort != 51820 {
		t.Fatalf("got %+v", iface)
	}
	if !strings.Contains(string(conf), "-o ens5 -j MASQUERADE") {
		t.Fatal("NAT not using the detected default interface")
	}
	for _, p := range []string{m.confPath(), m.settingsPath(), filepath.Join(m.Dir, "server_public.key")} {
		if got := mode(t, p); got != 0o600 {
			t.Errorf("%s mode %o, want 600", p, got)
		}
	}
	if got := mode(t, m.clientsDir()); got != 0o700 {
		t.Errorf("clients dir mode %o, want 700", got)
	}
	priv, _ := wgkey.Parse(iface.PrivateKey)
	pub, _ := priv.Public()
	saved, _ := os.ReadFile(filepath.Join(m.Dir, "server_public.key"))
	if strings.TrimSpace(string(saved)) != pub.String() {
		t.Fatal("server_public.key does not match the private key")
	}
	if fwd, _ := os.ReadFile(m.SysctlPath); string(fwd) != "net.ipv4.ip_forward=1\n" {
		t.Fatalf("sysctl file: %q", fwd)
	}
	want := []string{"sysctl -p " + m.SysctlPath, "systemctl enable --now wg-quick@wg0"}
	if strings.Join(r.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", r.ran, want)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	before, _ := os.ReadFile(m.confPath())
	if err := m.Init(InitOptions{Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820}); err == nil {
		t.Fatal("second init succeeded")
	}
	after, _ := os.ReadFile(m.confPath())
	if !bytes.Equal(before, after) {
		t.Fatal("server config (and its private key) was changed")
	}
}

func TestInitValidatesInput(t *testing.T) {
	cases := map[string]InitOptions{
		"network address": {Address: netip.MustParsePrefix("10.8.0.0/24"), Port: 51820},
		"tiny subnet":     {Address: netip.MustParsePrefix("10.8.0.1/31"), Port: 51820},
		"bad port":        {Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 70000},
		"bad dns":         {Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820, DNS: "1.1.1.1\nPostUp = rm -rf /"},
		"bad endpoint":    {Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820, Endpoint: "x\n[Peer]"},
		"bad wan iface":   {Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820, WANIface: "eth0; reboot"},
	}
	for name, o := range cases {
		m, _, _ := newTestManager(t)
		if err := m.Init(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(m.confPath()); err == nil {
			t.Errorf("%s: wrote a config anyway", name)
		}
	}
}

func TestInitFailsWithoutDefaultRoute(t *testing.T) {
	m, r, _ := newTestManager(t)
	r.route = ""
	if err := m.Init(InitOptions{Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820}); err == nil {
		t.Fatal("init without a WAN interface would produce a broken NAT rule")
	}
}

func TestAddProducesWorkingPair(t *testing.T) {
	m, r, _ := newTestManager(t)
	initServer(t, m)
	r.up = true

	client, err := m.Add("laptop")
	if err != nil {
		t.Fatal(err)
	}
	serverConf, _ := os.ReadFile(m.confPath())
	peers, _ := wgconf.ParsePeers(string(serverConf))
	if len(peers) != 1 || peers[0].IP.String() != "10.8.0.2" {
		t.Fatalf("peers %+v", peers)
	}

	// The keys on each side must actually pair up.
	clientPriv, _ := wgkey.Parse(field(client, "PrivateKey"))
	clientPub, _ := clientPriv.Public()
	if clientPub.String() != peers[0].PublicKey {
		t.Fatal("server peer key does not match client private key")
	}
	srvIface, _ := wgconf.ParseInterface(string(serverConf))
	srvPriv, _ := wgkey.Parse(srvIface.PrivateKey)
	srvPub, _ := srvPriv.Public()
	if field(client, "PublicKey") != srvPub.String() {
		t.Fatal("client has the wrong server public key")
	}
	if field(client, "PresharedKey") != peers[0].PresharedKey {
		t.Fatal("preshared keys differ")
	}
	if field(client, "Endpoint") != "203.0.113.7:51820" {
		t.Fatalf("endpoint %q", field(client, "Endpoint"))
	}
	if got := mode(t, m.clientPath("laptop")); got != 0o600 {
		t.Fatalf("client config mode %o", got)
	}
	last := r.ran[len(r.ran)-1]
	if !strings.HasPrefix(last, "wg syncconf wg0 ") {
		t.Fatalf("peer not applied live; last command %q", last)
	}
	// The temp file holding the stripped config (with private key) is gone.
	if matches, _ := filepath.Glob(filepath.Join(m.Dir, ".syncconf-*")); len(matches) != 0 {
		t.Fatalf("leftover temp files: %v", matches)
	}
}

func TestAddAllocatesAndReusesAddresses(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	for _, n := range []string{"a", "b", "c"} {
		if _, err := m.Add(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Revoke("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("d"); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(m.confPath())
	peers, _ := wgconf.ParsePeers(string(conf))
	got := map[string]string{}
	for _, p := range peers {
		got[p.Name] = p.IP.String()
	}
	if got["a"] != "10.8.0.2" || got["d"] != "10.8.0.3" || got["c"] != "10.8.0.4" || len(got) != 3 {
		t.Fatalf("allocation: %v", got)
	}
}

func TestAddRejectsDuplicatesAndBadNames(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	if _, err := m.Add("laptop"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.confPath())
	for _, n := range []string{"laptop", "../../etc/passwd", "x\n# END client-laptop"} {
		if _, err := m.Add(n); err == nil {
			t.Errorf("Add(%q) succeeded", n)
		}
	}
	after, _ := os.ReadFile(m.confPath())
	if !bytes.Equal(before, after) {
		t.Fatal("server config changed by a rejected add")
	}
}

func TestAddBeforeInit(t *testing.T) {
	m, _, _ := newTestManager(t)
	if _, err := m.Add("laptop"); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentAddsNeverShareAnIP(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mm := *m
			mm.Out = &bytes.Buffer{}
			// Contended adds fail fast on the lock; retry like a user would.
			for {
				if _, err := mm.Add("c" + string(rune('a'+i))); err == nil || !strings.Contains(err.Error(), "another wgm") {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	conf, _ := os.ReadFile(m.confPath())
	peers, err := wgconf.ParsePeers(string(conf))
	if err != nil || len(peers) != 20 {
		t.Fatalf("%v: %d peers", err, len(peers))
	}
	seen := map[netip.Addr]bool{}
	for _, p := range peers {
		if seen[p.IP] {
			t.Fatalf("duplicate IP %s", p.IP)
		}
		seen[p.IP] = true
	}
}

func TestRevoke(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	m.Add("laptop")
	m.Add("phone")
	if err := m.Revoke("laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.clientPath("laptop")); !os.IsNotExist(err) {
		t.Fatal("client config not deleted")
	}
	conf, _ := os.ReadFile(m.confPath())
	peers, _ := wgconf.ParsePeers(string(conf))
	if len(peers) != 1 || peers[0].Name != "phone" {
		t.Fatalf("peers %+v", peers)
	}
	if err := m.Revoke("laptop"); err == nil {
		t.Fatal("revoked twice")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	m, r, out := newTestManager(t)
	m.DryRun = true
	if err := m.Init(InitOptions{Address: netip.MustParsePrefix("10.8.0.1/24"), Port: 51820}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("dry run created the config directory")
	}
	if len(r.ran) != 2 || !strings.Contains(out.String(), "[dry-run] would write") {
		t.Fatalf("dry run output:\n%s", out)
	}

	m.DryRun = false
	initServer(t, m)
	m.DryRun = true
	before, _ := os.ReadFile(m.confPath())
	if _, err := m.Add("laptop"); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke("nobody"); err == nil {
		t.Fatal("dry-run revoke of a missing client succeeded")
	}
	after, _ := os.ReadFile(m.confPath())
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run add changed the server config")
	}
	if _, err := os.Stat(m.clientPath("laptop")); !os.IsNotExist(err) {
		t.Fatal("dry-run add wrote a client config")
	}
}

func TestManagesServerCreatedByBashScripts(t *testing.T) {
	m, _, _ := newTestManager(t)
	os.MkdirAll(m.clientsDir(), 0o700)
	priv, _ := wgkey.NewPrivate()
	bash := "[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\nPrivateKey = " + priv.String() +
		"\n\n# BEGIN client-old\n[Peer]\nPublicKey = abc=\nPresharedKey = def=\nAllowedIPs = 10.8.0.2/32\n# END client-old\n"
	os.WriteFile(m.confPath(), []byte(bash), 0o600)

	if _, err := m.Add("new"); err != nil {
		t.Fatal(err)
	}
	// No wgm.json existed, so the endpoint was detected and saved.
	if s, _ := os.ReadFile(m.settingsPath()); !strings.Contains(string(s), "203.0.113.7") {
		t.Fatalf("settings: %s", s)
	}
	if err := m.Revoke("old"); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(m.confPath())
	peers, _ := wgconf.ParsePeers(string(conf))
	if len(peers) != 1 || peers[0].Name != "new" || peers[0].IP.String() != "10.8.0.3" {
		t.Fatalf("peers %+v", peers)
	}
}

func TestListMergesLiveState(t *testing.T) {
	m, r, _ := newTestManager(t)
	initServer(t, m)
	m.Add("laptop")
	m.Add("phone")
	conf, _ := os.ReadFile(m.confPath())
	peers, _ := wgconf.ParsePeers(string(conf))

	now := time.Unix(1_800_000_000, 0)
	r.up = true
	r.dump = "srvpriv\tsrvpub\t51820\toff\n" +
		peers[0].PublicKey + "\tpsk\t198.51.100.4:41000\t10.8.0.2/32\t" + strconv.FormatInt(now.Unix()-30, 10) + "\t1024\t2048\t0\n" +
		peers[1].PublicKey + "\tpsk\t(none)\t10.8.0.3/32\t0\t0\t0\t0\n"

	got, err := m.List(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Online || got[0].Endpoint != "198.51.100.4:41000" || got[0].RxBytes != 1024 || got[0].TxBytes != 2048 {
		t.Fatalf("laptop: %+v", got[0])
	}
	if got[1].Online || got[1].Endpoint != "" || !got[1].LastHandshake.IsZero() {
		t.Fatalf("phone: %+v", got[1])
	}

	r.up = false // interface down: still lists configured clients
	got, err = m.List(now)
	if err != nil || len(got) != 2 || got[0].Online {
		t.Fatalf("down: %v %+v", err, got)
	}
}

func TestClientConfig(t *testing.T) {
	m, _, _ := newTestManager(t)
	initServer(t, m)
	want, _ := m.Add("laptop")
	if got, err := m.ClientConfig("laptop"); err != nil || got != want {
		t.Fatalf("%v", err)
	}
	if _, err := m.ClientConfig("../wg0"); err == nil {
		t.Fatal("path traversal allowed")
	}
}

func field(conf, key string) string {
	for _, l := range strings.Split(conf, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
