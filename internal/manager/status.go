package manager

import (
	"strconv"
	"strings"
	"time"

	"github.com/yorick1125/self-hosted-vpn/internal/wgconf"
)

// PeerStatus combines a configured client with its live state.
type PeerStatus struct {
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Online        bool      `json:"online"`
}

// A peer that has not completed a handshake for this long is offline.
// WireGuard re-handshakes every 2 minutes on an active session.
const onlineWindow = 3 * time.Minute

// List returns every managed client. Live fields are empty when the
// interface is down.
func (m *Manager) List(now time.Time) ([]PeerStatus, error) {
	conf, _, err := m.readServer()
	if err != nil {
		return nil, err
	}
	peers, err := wgconf.ParsePeers(conf)
	if err != nil {
		return nil, err
	}
	live := map[string]PeerStatus{}
	if out, err := m.Runner.Output("wg", "show", m.Iface, "dump"); err == nil {
		live = parseDump(string(out))
	}
	res := make([]PeerStatus, 0, len(peers))
	for _, p := range peers {
		s := live[p.PublicKey]
		s.Name, s.IP, s.PublicKey = p.Name, p.IP.String(), p.PublicKey
		s.Online = !s.LastHandshake.IsZero() && now.Sub(s.LastHandshake) < onlineWindow
		res = append(res, s)
	}
	return res, nil
}

// parseDump reads `wg show <iface> dump`. The first line describes the
// interface; each following line is a peer, tab-separated:
// public-key preshared-key endpoint allowed-ips latest-handshake rx tx keepalive
func parseDump(out string) map[string]PeerStatus {
	res := map[string]PeerStatus{}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines[min(1, len(lines)):] {
		f := strings.Split(l, "\t")
		if len(f) < 8 {
			continue
		}
		var s PeerStatus
		if f[2] != "(none)" {
			s.Endpoint = f[2]
		}
		if ts, _ := strconv.ParseInt(f[4], 10, 64); ts > 0 {
			s.LastHandshake = time.Unix(ts, 0)
		}
		s.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		s.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		res[f[0]] = s
	}
	return res
}
