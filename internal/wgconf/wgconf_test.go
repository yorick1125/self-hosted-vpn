package wgconf

import (
	"net/netip"
	"strings"
	"testing"
)

// Config as produced by scripts/01-install-wireguard.sh + add-client.sh.
const bashConf = `[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT

# BEGIN client-laptop
[Peer]
PublicKey = bGFwdG9wbGFwdG9wbGFwdG9wbGFwdG9wbGFwdG9wMDA=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMDA=
AllowedIPs = 10.8.0.2/32
# END client-laptop

# BEGIN client-phone
[Peer]
PublicKey = cGhvbmVwaG9uZXBob25lcGhvbmVwaG9uZXBob25lMDA=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMDA=
AllowedIPs = 10.8.0.3/32
# END client-phone
`

func TestParseInterface(t *testing.T) {
	iface, err := ParseInterface(bashConf)
	if err != nil {
		t.Fatal(err)
	}
	if iface.Address.String() != "10.8.0.1/24" || iface.ListenPort != 51820 || !strings.HasSuffix(iface.PrivateKey, "=") {
		t.Fatalf("got %+v", iface)
	}
}

func TestParsePeersReadsBashFormat(t *testing.T) {
	peers, err := ParsePeers(bashConf)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].Name != "laptop" || peers[1].IP.String() != "10.8.0.3" {
		t.Fatalf("got %+v", peers)
	}
	if peers[0].PublicKey != "bGFwdG9wbGFwdG9wbGFwdG9wbGFwdG9wbGFwdG9wMDA=" {
		t.Fatalf("base64 padding lost: %q", peers[0].PublicKey)
	}
}

func TestParsePeersRejectsBrokenMarkers(t *testing.T) {
	for _, conf := range []string{
		"# BEGIN client-a\n[Peer]\n",
		"# END client-a\n",
		"# BEGIN client-a\n# BEGIN client-b\n# END client-b\n# END client-a\n",
	} {
		if _, err := ParsePeers(conf); err == nil {
			t.Errorf("accepted malformed config:\n%s", conf)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"laptop", "j-phone", "Work_PC2", "a"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc", "a/b", "-x", "x\n# END client-x", "has space", strings.Repeat("a", 33)} {
		if ValidateName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNextIP(t *testing.T) {
	subnet := netip.MustParsePrefix("10.8.0.1/24")
	server := netip.MustParseAddr("10.8.0.1")
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	got, _ := NextIP(subnet, server, nil)
	if got != ip("10.8.0.2") {
		t.Fatalf("empty: got %s", got)
	}
	// Reuses the gap left by a revoked client.
	got, _ = NextIP(subnet, server, []netip.Addr{ip("10.8.0.2"), ip("10.8.0.4")})
	if got != ip("10.8.0.3") {
		t.Fatalf("gap: got %s", got)
	}
	// /30 has two hosts: server takes .1, client gets .2, then it's full.
	small := netip.MustParsePrefix("10.9.0.0/30")
	if _, err := NextIP(small, ip("10.9.0.1"), []netip.Addr{ip("10.9.0.2")}); err == nil {
		t.Fatal("expected exhaustion error, never the broadcast address")
	}
}

func TestUsedIPsIncludesUnmanagedPeers(t *testing.T) {
	conf := bashConf + "\n[Peer]\nPublicKey = x\nAllowedIPs = 10.8.0.9/32, 192.168.5.0/24\n"
	used := UsedIPs(conf)
	if len(used) != 3 || used[2].String() != "10.8.0.9" {
		t.Fatalf("got %v", used)
	}
}

func TestAppendThenRemoveRoundTrips(t *testing.T) {
	base := strings.SplitN(bashConf, "\n# BEGIN", 2)[0] + "\n"
	p := Peer{Name: "tablet", PublicKey: "pub=", PresharedKey: "psk=", IP: netip.MustParseAddr("10.8.0.5")}

	added := AppendPeer(base, p)
	peers, err := ParsePeers(added)
	if err != nil || len(peers) != 1 || peers[0] != p {
		t.Fatalf("append: %v %+v", err, peers)
	}
	removed, ok := RemovePeer(added, "tablet")
	if !ok || strings.TrimSpace(removed) != strings.TrimSpace(base) {
		t.Fatalf("remove did not restore original:\n%q\nvs\n%q", removed, base)
	}
}

func TestRemovePeerLeavesOthersAlone(t *testing.T) {
	out, ok := RemovePeer(bashConf, "laptop")
	if !ok {
		t.Fatal("laptop not found")
	}
	peers, _ := ParsePeers(out)
	if len(peers) != 1 || peers[0].Name != "phone" {
		t.Fatalf("got %+v", peers)
	}
	if _, ok := RemovePeer(out, "laptop"); ok {
		t.Fatal("removed twice")
	}
	// A name that is a prefix of another must not match it.
	if _, ok := RemovePeer(bashConf, "lap"); ok {
		t.Fatal("prefix name matched")
	}
}

func TestRenderedConfigsParse(t *testing.T) {
	srv := RenderServer(ServerParams{Address: netip.MustParsePrefix("10.8.0.1/24"), ListenPort: 51820, PrivateKey: "k=", WANIface: "eth0"})
	iface, err := ParseInterface(srv)
	if err != nil || iface.ListenPort != 51820 {
		t.Fatalf("%v %+v", err, iface)
	}
	if !strings.Contains(srv, "-o eth0 -j MASQUERADE") || !strings.Contains(srv, "-i %i ") {
		t.Fatalf("NAT rules wrong:\n%s", srv)
	}
	cli := RenderClient(ClientParams{Address: netip.MustParseAddr("10.8.0.2"), DNS: "1.1.1.1", Endpoint: "vpn.example.com:51820"})
	for _, want := range []string{"Address = 10.8.0.2/32", "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = vpn.example.com:51820", "DNS = 1.1.1.1"} {
		if !strings.Contains(cli, want) {
			t.Errorf("client config missing %q", want)
		}
	}
}
