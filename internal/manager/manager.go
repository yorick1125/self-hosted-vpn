// Package manager implements wgm's commands on top of the local WireGuard
// interface. It runs on the VPN server itself.
package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yorick1125/self-hosted-vpn/internal/wgconf"
	"github.com/yorick1125/self-hosted-vpn/internal/wgkey"
)

// Manager holds everything a command needs. Tests swap Runner, Dir and
// LookupPublicIP so nothing touches the real system.
type Manager struct {
	Dir        string // /etc/wireguard
	Iface      string // wg0
	SysctlPath string // /etc/sysctl.d/99-wireguard.conf
	DryRun     bool
	Runner     Runner
	Out        io.Writer
	// LookupPublicIP detects the endpoint when none is configured.
	LookupPublicIP func() (string, error)
}

// Settings that are not part of the WireGuard config itself, stored in
// <Dir>/wgm.json.
type Settings struct {
	Endpoint string `json:"endpoint"` // host or IP clients connect to
	DNS      string `json:"dns"`      // DNS servers pushed to clients
}

const DefaultDNS = "1.1.1.1, 1.0.0.1"

var ErrNotInitialized = errors.New("no server config found; run `wgm init` first")

func (m *Manager) confPath() string           { return filepath.Join(m.Dir, m.Iface+".conf") }
func (m *Manager) clientsDir() string         { return filepath.Join(m.Dir, "clients") }
func (m *Manager) settingsPath() string       { return filepath.Join(m.Dir, "wgm.json") }
func (m *Manager) clientPath(n string) string { return filepath.Join(m.clientsDir(), n+".conf") }

func (m *Manager) logf(format string, a ...any) { fmt.Fprintf(m.Out, format+"\n", a...) }

func (m *Manager) write(path string, data []byte) error {
	if m.DryRun {
		m.logf("  [dry-run] would write %s (%d bytes, mode 600)", path, len(data))
		return nil
	}
	return writeFileAtomic(path, data, 0o600)
}

func (m *Manager) remove(path string) error {
	if m.DryRun {
		m.logf("  [dry-run] would remove %s", path)
		return nil
	}
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) mkdir(path string) error {
	if m.DryRun {
		m.logf("  [dry-run] would create %s (mode 700)", path)
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

// InitOptions configures a new server.
type InitOptions struct {
	Address  netip.Prefix // server tunnel address and subnet, e.g. 10.8.0.1/24
	Port     int
	Endpoint string // public host/IP; detected if empty
	DNS      string
	WANIface string // detected from the default route if empty
}

// Init writes the server config, enables IP forwarding and starts the
// interface. It refuses to overwrite an existing config.
func (m *Manager) Init(o InitOptions) error {
	if _, err := os.Stat(m.confPath()); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite (revoke clients or remove it by hand)", m.confPath())
	}
	if !o.Address.IsValid() || !o.Address.Addr().Is4() || o.Address.Bits() > 30 {
		return fmt.Errorf("address must be an IPv4 prefix of /30 or larger, e.g. 10.8.0.1/24")
	}
	if o.Address.Addr() == o.Address.Masked().Addr() {
		return fmt.Errorf("address %s is the network address; use a host address such as %s", o.Address, o.Address.Addr().Next())
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("invalid port %d", o.Port)
	}
	if o.DNS == "" {
		o.DNS = DefaultDNS
	}
	if err := validateDNS(o.DNS); err != nil {
		return err
	}
	if o.WANIface == "" {
		iface, err := m.defaultRouteIface()
		if err != nil {
			return err
		}
		o.WANIface = iface
	}
	if !validIfaceName(o.WANIface) {
		return fmt.Errorf("invalid network interface name %q", o.WANIface)
	}
	if o.Endpoint == "" {
		ip, err := m.LookupPublicIP()
		if err != nil {
			return err
		}
		o.Endpoint = ip
	}
	if err := validateHost(o.Endpoint); err != nil {
		return err
	}

	unlock, err := m.lockDir()
	if err != nil {
		return err
	}
	defer unlock()

	priv, err := wgkey.NewPrivate()
	if err != nil {
		return err
	}
	pub, err := priv.Public()
	if err != nil {
		return err
	}
	conf := wgconf.RenderServer(wgconf.ServerParams{Address: o.Address, ListenPort: o.Port, PrivateKey: priv.String(), WANIface: o.WANIface})
	settings, _ := json.MarshalIndent(Settings{Endpoint: o.Endpoint, DNS: o.DNS}, "", "  ")

	if err := m.mkdir(m.clientsDir()); err != nil {
		return err
	}
	if err := m.write(m.confPath(), []byte(conf)); err != nil {
		return err
	}
	// Same file the Bash scripts read, so they keep working alongside wgm.
	if err := m.write(filepath.Join(m.Dir, "server_public.key"), []byte(pub.String()+"\n")); err != nil {
		return err
	}
	if err := m.write(m.settingsPath(), append(settings, '\n')); err != nil {
		return err
	}
	if m.DryRun {
		m.logf("  [dry-run] would write %s: net.ipv4.ip_forward=1", m.SysctlPath)
	} else {
		if err := os.MkdirAll(filepath.Dir(m.SysctlPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(m.SysctlPath, []byte("net.ipv4.ip_forward=1\n"), 0o644); err != nil {
			return err
		}
	}
	if err := m.Runner.Run("sysctl", "-p", m.SysctlPath); err != nil {
		return err
	}
	if err := m.Runner.Run("systemctl", "enable", "--now", "wg-quick@"+m.Iface); err != nil {
		return err
	}
	m.logf("Server ready on %s (UDP %d), subnet %s, NAT via %s.", m.Iface, o.Port, o.Address.Masked(), o.WANIface)
	m.logf("Clients will connect to %s:%d. Server public key: %s", o.Endpoint, o.Port, pub)
	return nil
}

// Add provisions a client and returns its config. The new peer is applied
// to the running interface without dropping existing connections.
func (m *Manager) Add(name string) (string, error) {
	if err := wgconf.ValidateName(name); err != nil {
		return "", err
	}
	unlock, err := m.lockDir()
	if err != nil {
		return "", err
	}
	defer unlock()

	conf, iface, err := m.readServer()
	if err != nil {
		return "", err
	}
	peers, err := wgconf.ParsePeers(conf)
	if err != nil {
		return "", fmt.Errorf("%s: %w", m.confPath(), err)
	}
	for _, p := range peers {
		if p.Name == name {
			return "", fmt.Errorf("client %q already exists (%s)", name, p.IP)
		}
	}
	if _, err := os.Stat(m.clientPath(name)); err == nil {
		return "", fmt.Errorf("client config %s already exists", m.clientPath(name))
	}
	ip, err := wgconf.NextIP(iface.Address, iface.Address.Addr(), wgconf.UsedIPs(conf))
	if err != nil {
		return "", err
	}
	settings, err := m.settings(iface)
	if err != nil {
		return "", err
	}
	serverPriv, err := wgkey.Parse(iface.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("server PrivateKey: %w", err)
	}
	serverPub, _ := serverPriv.Public()
	priv, err := wgkey.NewPrivate()
	if err != nil {
		return "", err
	}
	pub, _ := priv.Public()
	psk, err := wgkey.NewPreshared()
	if err != nil {
		return "", err
	}

	client := wgconf.RenderClient(wgconf.ClientParams{
		PrivateKey:      priv.String(),
		Address:         ip,
		DNS:             settings.DNS,
		ServerPublicKey: serverPub.String(),
		PresharedKey:    psk.String(),
		Endpoint:        net.JoinHostPort(settings.Endpoint, strconv.Itoa(iface.ListenPort)),
	})
	updated := wgconf.AppendPeer(conf, wgconf.Peer{Name: name, PublicKey: pub.String(), PresharedKey: psk.String(), IP: ip})

	// Client file first: if the server write then fails, roll it back so no
	// orphaned config with a working-looking key is left behind.
	if err := m.mkdir(m.clientsDir()); err != nil {
		return "", err
	}
	if err := m.write(m.clientPath(name), []byte(client)); err != nil {
		return "", err
	}
	if err := m.write(m.confPath(), []byte(updated)); err != nil {
		m.remove(m.clientPath(name))
		return "", err
	}
	if err := m.sync(); err != nil {
		return "", err
	}
	m.logf("Added %s with IP %s. Config: %s", name, ip, m.clientPath(name))
	return client, nil
}

// Revoke removes a client from the server and deletes its config. The peer
// is dropped from the live interface immediately.
func (m *Manager) Revoke(name string) error {
	if err := wgconf.ValidateName(name); err != nil {
		return err
	}
	unlock, err := m.lockDir()
	if err != nil {
		return err
	}
	defer unlock()

	conf, _, err := m.readServer()
	if err != nil {
		return err
	}
	updated, ok := wgconf.RemovePeer(conf, name)
	if !ok {
		return fmt.Errorf("no such client: %s", name)
	}
	if err := m.write(m.confPath(), []byte(updated)); err != nil {
		return err
	}
	if err := m.remove(m.clientPath(name)); err != nil {
		return err
	}
	if err := m.sync(); err != nil {
		return err
	}
	m.logf("Revoked %s.", name)
	return nil
}

// ClientConfig returns a previously generated client config.
func (m *Manager) ClientConfig(name string) (string, error) {
	if err := wgconf.ValidateName(name); err != nil {
		return "", err
	}
	b, err := os.ReadFile(m.clientPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("no config for client %q", name)
	}
	return string(b), err
}

func (m *Manager) lockDir() (func(), error) {
	if m.DryRun {
		return func() {}, nil
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, err
	}
	return lock(m.Dir)
}

func (m *Manager) readServer() (string, wgconf.Interface, error) {
	b, err := os.ReadFile(m.confPath())
	if errors.Is(err, fs.ErrNotExist) {
		return "", wgconf.Interface{}, ErrNotInitialized
	}
	if err != nil {
		return "", wgconf.Interface{}, err
	}
	iface, err := wgconf.ParseInterface(string(b))
	if err != nil {
		return "", iface, fmt.Errorf("%s: %w", m.confPath(), err)
	}
	if iface.ListenPort == 0 {
		iface.ListenPort = 51820
	}
	return string(b), iface, nil
}

// settings loads wgm.json. A server set up by the Bash scripts has none, so
// the endpoint is detected once and saved.
func (m *Manager) settings(iface wgconf.Interface) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(m.settingsPath())
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s); err != nil {
			return s, fmt.Errorf("%s: %w", m.settingsPath(), err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return s, err
	}
	if s.DNS == "" {
		s.DNS = DefaultDNS
	}
	if s.Endpoint == "" {
		ip, err := m.LookupPublicIP()
		if err != nil {
			return s, err
		}
		s.Endpoint = ip
		out, _ := json.MarshalIndent(s, "", "  ")
		if err := m.write(m.settingsPath(), append(out, '\n')); err != nil {
			return s, err
		}
	}
	if err := validateHost(s.Endpoint); err != nil {
		return s, err
	}
	return s, validateDNS(s.DNS)
}

// sync applies the config file to the running interface with `wg syncconf`,
// which adds and removes peers without restarting the tunnel.
func (m *Manager) sync() error {
	if _, err := m.Runner.Output("wg", "show", m.Iface); err != nil {
		m.logf("Note: %s is not running; changes apply when it starts.", m.Iface)
		return nil
	}
	if m.DryRun {
		return m.Runner.Run("wg", "syncconf", m.Iface, "<(wg-quick strip "+m.confPath()+")")
	}
	stripped, err := m.Runner.Output("wg-quick", "strip", m.confPath())
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.Dir, ".syncconf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(stripped)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return m.Runner.Run("wg", "syncconf", m.Iface, tmp.Name())
}

func (m *Manager) defaultRouteIface() (string, error) {
	out, err := m.Runner.Output("ip", "-4", "route", "show", "default")
	if err == nil {
		f := strings.Fields(string(out))
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1], nil
			}
		}
	}
	// Without this the MASQUERADE rule is malformed: the tunnel comes up but
	// routes nothing.
	return "", errors.New("could not find the default network interface; pass --wan-iface")
}

func validIfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// validateHost accepts an IP or a DNS name. It keeps newlines and other
// junk out of generated configs.
func validateHost(h string) error {
	if _, err := netip.ParseAddr(h); err == nil {
		return nil
	}
	if len(h) > 0 && len(h) <= 253 && !strings.HasPrefix(h, "-") {
		ok := true
		for _, r := range h {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("invalid endpoint %q: want an IP address or hostname", h)
}

func validateDNS(s string) error {
	for _, part := range strings.Split(s, ",") {
		if _, err := netip.ParseAddr(strings.TrimSpace(part)); err != nil {
			return fmt.Errorf("invalid DNS server %q", strings.TrimSpace(part))
		}
	}
	return nil
}
