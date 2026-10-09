// Package wgconf reads and writes the WireGuard server config.
//
// Each client's [Peer] section is wrapped in "# BEGIN client-<name>" and
// "# END client-<name>" markers. That is the same layout the Bash scripts in
// scripts/ produce, so a server set up with either tool can be managed by the
// other.
package wgconf

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Client names end up in file paths and config comments, so they are limited
// to a conservative character set. This blocks path traversal ("../x") and
// marker injection (a name containing a newline or "# END").
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

// ValidateName returns an error unless name is a safe client name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid client name %q: use 1-32 letters, digits, '-' or '_', starting with a letter or digit", name)
	}
	return nil
}

// Peer is one client entry in the server config.
type Peer struct {
	Name         string
	PublicKey    string
	PresharedKey string
	IP           netip.Addr
}

// Interface holds the fields wgm needs from the server's [Interface] section.
type Interface struct {
	Address    netip.Prefix // server tunnel address, e.g. 10.8.0.1/24
	ListenPort int
	PrivateKey string
}

const (
	beginPrefix = "# BEGIN client-"
	endPrefix   = "# END client-"
)

// ParseInterface extracts the [Interface] fields from a server config.
func ParseInterface(conf string) (Interface, error) {
	var iface Interface
	section := ""
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		if section != "[interface]" {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "address":
			// Address may list several, comma-separated; take the first IPv4.
			for _, a := range strings.Split(v, ",") {
				p, err := netip.ParsePrefix(strings.TrimSpace(a))
				if err == nil && p.Addr().Is4() {
					iface.Address = p
					break
				}
			}
		case "listenport":
			fmt.Sscanf(v, "%d", &iface.ListenPort)
		case "privatekey":
			iface.PrivateKey = v
		}
	}
	if !iface.Address.IsValid() {
		return iface, errors.New("server config has no IPv4 Address in [Interface]")
	}
	if iface.PrivateKey == "" {
		return iface, errors.New("server config has no PrivateKey in [Interface]")
	}
	return iface, nil
}

// ParsePeers returns the managed (marker-wrapped) peers in conf, sorted by IP.
func ParsePeers(conf string) ([]Peer, error) {
	var peers []Peer
	var cur *Peer
	sc := bufio.NewScanner(strings.NewReader(conf))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, beginPrefix):
			if cur != nil {
				return nil, fmt.Errorf("line %d: client-%s block opened before client-%s was closed", n, strings.TrimPrefix(line, beginPrefix), cur.Name)
			}
			cur = &Peer{Name: strings.TrimPrefix(line, beginPrefix)}
		case strings.HasPrefix(line, endPrefix):
			name := strings.TrimPrefix(line, endPrefix)
			if cur == nil || cur.Name != name {
				return nil, fmt.Errorf("line %d: unexpected end marker for client-%s", n, name)
			}
			peers = append(peers, *cur)
			cur = nil
		case cur != nil:
			k, v, ok := splitKV(line)
			if !ok {
				continue
			}
			switch k {
			case "publickey":
				cur.PublicKey = v
			case "presharedkey":
				cur.PresharedKey = v
			case "allowedips":
				if p, err := netip.ParsePrefix(strings.Split(v, ",")[0]); err == nil {
					cur.IP = p.Addr()
				}
			}
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("client-%s block is never closed", cur.Name)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP.Less(peers[j].IP) })
	return peers, nil
}

// UsedIPs returns every /32 in any AllowedIPs line, including peers added by
// hand without markers, so allocation never hands out an address in use.
func UsedIPs(conf string) []netip.Addr {
	var used []netip.Addr
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		k, v, ok := splitKV(strings.TrimSpace(sc.Text()))
		if !ok || k != "allowedips" {
			continue
		}
		for _, part := range strings.Split(v, ",") {
			if p, err := netip.ParsePrefix(strings.TrimSpace(part)); err == nil && p.Bits() == 32 {
				used = append(used, p.Addr())
			}
		}
	}
	return used
}

// NextIP returns the lowest free host address in subnet. The network,
// broadcast and server addresses are never handed out. Gaps left by revoked
// clients are reused.
func NextIP(subnet netip.Prefix, server netip.Addr, used []netip.Addr) (netip.Addr, error) {
	subnet = subnet.Masked()
	taken := map[netip.Addr]bool{server: true}
	for _, a := range used {
		taken[a] = true
	}
	first := subnet.Addr().Next() // skip network address
	for a := first; subnet.Contains(a); a = a.Next() {
		if !subnet.Contains(a.Next()) {
			break // a is the broadcast address
		}
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free addresses left in %s", subnet)
}

// AppendPeer adds a marker-wrapped [Peer] section to conf.
func AppendPeer(conf string, p Peer) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(conf, "\n"))
	fmt.Fprintf(&b, "\n\n%s%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n%s%s\n",
		beginPrefix, p.Name, p.PublicKey, p.PresharedKey, p.IP, endPrefix, p.Name)
	return b.String()
}

// RemovePeer deletes the named peer's block. ok is false if it wasn't there.
func RemovePeer(conf, name string) (out string, ok bool) {
	lines := strings.Split(conf, "\n")
	kept := make([]string, 0, len(lines))
	inside := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == beginPrefix+name {
			inside, ok = true, true
			// Drop the blank separator line AppendPeer put before the block.
			if n := len(kept); n > 0 && strings.TrimSpace(kept[n-1]) == "" {
				kept = kept[:n-1]
			}
			continue
		}
		if inside {
			if t == endPrefix+name {
				inside = false
			}
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n"), ok
}

// ServerParams describes a new server config.
type ServerParams struct {
	Address    netip.Prefix
	ListenPort int
	PrivateKey string
	WANIface   string // interface that reaches the internet, for NAT
}

// RenderServer produces a server config with NAT so clients can reach the
// internet through the tunnel.
func RenderServer(p ServerParams) string {
	return fmt.Sprintf(`[Interface]
Address = %s
ListenPort = %d
PrivateKey = %s
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE
`, p.Address, p.ListenPort, p.PrivateKey, p.WANIface, p.WANIface)
}

// ClientParams describes a client config.
type ClientParams struct {
	PrivateKey      string
	Address         netip.Addr
	DNS             string
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string // host:port
}

// RenderClient produces a full-tunnel client config. All traffic, DNS
// included, goes through the VPN, which is what prevents DNS leaks.
func RenderClient(p ClientParams) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, p.PrivateKey, p.Address, p.DNS, p.ServerPublicKey, p.PresharedKey, p.Endpoint)
}

func splitKV(line string) (key, val string, ok bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v), true
}
