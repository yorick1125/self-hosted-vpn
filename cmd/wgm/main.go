// Command wgm manages a WireGuard VPN server from the server itself.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yorick1125/self-hosted-vpn/internal/manager"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const defaultDir = "/etc/wireguard"

const usage = `wgm - manage a self-hosted WireGuard VPN from the server

Usage:
  wgm init   [--address 10.8.0.1/24] [--port 51820] [--endpoint HOST] [--dns IPs] [--wan-iface IF]
  wgm add    <name> [--qr]       create a client and print its config
  wgm list   [--json]            clients with live status (alias: ls)
  wgm show   <name> [--qr]       print an existing client's config
  wgm revoke <name>              remove a client and cut its access (alias: rm)
  wgm version

Flags for every command:
  --dir DIR      WireGuard config directory (default /etc/wireguard, env WG_DIR)
  --iface NAME   WireGuard interface (default wg0, env WG_INTERFACE)
  --dry-run      print what would change without changing anything
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "wgm:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("missing command")
	}
	cmd, args := args[0], args[1:]

	fs := flag.NewFlagSet("wgm "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	dir := fs.String("dir", envOr("WG_DIR", defaultDir), "")
	iface := fs.String("iface", envOr("WG_INTERFACE", "wg0"), "")
	dryRun := fs.Bool("dry-run", false, "")
	qr := fs.Bool("qr", false, "")
	asJSON := fs.Bool("json", false, "")
	address := fs.String("address", "10.8.0.1/24", "")
	port := fs.Int("port", 51820, "")
	endpoint := fs.String("endpoint", "", "")
	dns := fs.String("dns", manager.DefaultDNS, "")
	wan := fs.String("wan-iface", "", "")

	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "version", "--version":
		fmt.Fprintln(stdout, "wgm", version)
		return nil
	}

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 && !*dryRun && *dir == defaultDir {
		return fmt.Errorf("%s is root-only; run with sudo (or --dry-run to preview)", *dir)
	}

	m := &manager.Manager{
		Dir: *dir, Iface: *iface, DryRun: *dryRun,
		SysctlPath:     envOr("SYSCTL_CONF", "/etc/sysctl.d/99-wireguard.conf"),
		Runner:         manager.ExecRunner{DryRun: *dryRun, Log: stderr},
		Out:            stderr,
		LookupPublicIP: manager.LookupPublicIP,
	}
	// Status messages go to stderr so `wgm add x > x.conf` captures only the config.

	switch cmd {
	case "init":
		if err := wantArgs(pos, 0, "init"); err != nil {
			return err
		}
		addr, err := netip.ParsePrefix(*address)
		if err != nil {
			return fmt.Errorf("--address: %w", err)
		}
		if !*dryRun {
			for _, bin := range []string{"wg", "wg-quick"} {
				if _, err := exec.LookPath(bin); err != nil {
					return fmt.Errorf("%s not found; install WireGuard first (apt install wireguard-tools / dnf install wireguard-tools)", bin)
				}
			}
		}
		return m.Init(manager.InitOptions{Address: addr, Port: *port, Endpoint: *endpoint, DNS: *dns, WANIface: *wan})

	case "add":
		if err := wantArgs(pos, 1, "add <name>"); err != nil {
			return err
		}
		conf, err := m.Add(pos[0])
		if err != nil || *dryRun {
			return err
		}
		return printConfig(stdout, stderr, conf, *qr)

	case "show":
		if err := wantArgs(pos, 1, "show <name>"); err != nil {
			return err
		}
		conf, err := m.ClientConfig(pos[0])
		if err != nil {
			return err
		}
		return printConfig(stdout, stderr, conf, *qr)

	case "revoke", "rm":
		if err := wantArgs(pos, 1, "revoke <name>"); err != nil {
			return err
		}
		return m.Revoke(pos[0])

	case "list", "ls":
		if err := wantArgs(pos, 0, "list"); err != nil {
			return err
		}
		peers, err := m.List(time.Now())
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(peers)
		}
		return printTable(stdout, peers, time.Now())
	}

	fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

// parseInterspersed lets flags appear before or after positional arguments
// (`wgm add laptop --qr` and `wgm add --qr laptop` both work).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func wantArgs(pos []string, n int, form string) error {
	if len(pos) != n {
		return fmt.Errorf("usage: wgm %s", form)
	}
	return nil
}

func printConfig(stdout, stderr io.Writer, conf string, qr bool) error {
	if !qr {
		_, err := fmt.Fprint(stdout, conf)
		return err
	}
	if _, err := exec.LookPath("qrencode"); err != nil {
		return errors.New("qrencode not found; install it (apt install qrencode) or drop --qr")
	}
	c := exec.Command("qrencode", "-t", "ansiutf8")
	c.Stdin, c.Stdout, c.Stderr = strings.NewReader(conf), stdout, stderr
	return c.Run()
}

func printTable(w io.Writer, peers []manager.PeerStatus, now time.Time) error {
	if len(peers) == 0 {
		fmt.Fprintln(w, "No clients yet. Add one with: wgm add <name>")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tSTATUS\tLAST HANDSHAKE\tRX\tTX\tENDPOINT")
	for _, p := range peers {
		status, hs := "offline", "never"
		if p.Online {
			status = "online"
		}
		if !p.LastHandshake.IsZero() {
			hs = now.Sub(p.LastHandshake).Round(time.Second).String() + " ago"
		}
		ep := p.Endpoint
		if ep == "" {
			ep = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.IP, status, hs, humanBytes(p.RxBytes), humanBytes(p.TxBytes), ep)
	}
	return tw.Flush()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
