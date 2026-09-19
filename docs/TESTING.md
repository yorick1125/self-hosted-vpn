# Testing

These scripts install packages, rewrite `/etc`, change firewall rules and restart SSH. Getting
one wrong on a remote server can lock you out of it permanently. So there are three levels of
checking, cheapest first.

| Level | What it proves | Needs |
|---|---|---|
| Test suite | The logic is right: addresses, config contents, ordering, failure handling | bash |
| Dry run | What a script *would* do on a real host, line by line | bash |
| Real deploy | That WireGuard actually carries traffic | A Linux VPS |

The first two run on any machine, including Windows under Git Bash. Only the third needs a
server.

---

## 1. Test suite

```bash
./tests/run-tests.sh            # everything
./tests/run-tests.sh clients    # just tests/test-clients.sh
```

### How it works

The scripts are run **for real** — not simulated — inside a sandbox:

- `WG_DIR`, `CLIENTS_DIR`, `SSHD_CONFIG`, `FAIL2BAN_JAIL` and `SYSCTL_CONF` are redirected into
  a temp directory, so nothing touches `/etc`.
- `tests/mocks/bin` goes on `PATH` ahead of everything else, supplying fake `wg`, `wg-quick`,
  `systemctl`, `apt-get`, `ufw`, `ip`, `curl`, `sshd` and friends. Each one logs how it was
  called, so tests can assert on what the script *tried* to do.
- `WG_TEST=1` skips the root check. Nothing being touched requires privileges.

That means the assertions are about real generated output — the actual `wg0.conf` the script
writes, the actual client config, the actual order of `ufw` calls.

### What it covers

**Install** — keys are generated, the interface config is correct, the NAT rule names a real
interface rather than an empty string, and a second run is idempotent (doesn't rotate keys or
rewrite config).

**Clients** — the first client gets `.2` because the server holds `.1`, the second advances,
peer entries are scoped to a `/32`, client configs route everything through the tunnel and set
DNS, duplicates are refused, revocation removes both the peer block and the config file while
leaving other clients alone, and a client config never contains the server's private key.

**Hardening** — SSH is allowed through the firewall *before* inbound is denied (the reverse
order would drop your own connection mid-run), root login and password auth are disabled, the
original `sshd_config` is backed up, and the backup keeps the original contents.

And the one that matters most:

**A broken `sshd_config` never reaches a restart.** The script runs `sshd -t` first; if
validation fails it restores the backup and aborts. The test forces a validation failure and
asserts that no restart was attempted. Without that guard, a bad `sed` plus a restart is an
unrecoverable lockout on a remote box.

### Adding a test

```bash
it "describes what should be true"
assert_contains "$(cat "$SOME_FILE")" "expected string"
```

Available: `assert_eq`, `assert_contains`, `assert_not_contains`, `assert_file_exists`,
`assert_file_missing`, `assert_fails <expected-stderr> <cmd...>`.

---

## 2. Dry run

Every script honours `DRY_RUN=1`. It prints each system-changing command instead of running it,
and doesn't write anything:

```bash
DRY_RUN=1 ./scripts/01-install-wireguard.sh
```

```
  [dry-run] would create /etc/wireguard and /etc/wireguard/clients (mode 700)
  [dry-run] would generate a server keypair in /etc/wireguard
  [dry-run] would write /etc/wireguard/wg0.conf:
            Address = 10.8.0.1/24, ListenPort = 51820
            MASQUERADE via eth0
  [dry-run] sysctl -p /etc/sysctl.d/99-wireguard.conf
  [dry-run] systemctl enable --now wg-quick@wg0

Dry run complete. Nothing was installed, written, or started.
```

Dry run deliberately does not require Linux — the point is to preview from wherever you are
before touching the target.

---

## 3. Real deployment

Neither level above proves WireGuard moves packets. The mocks don't implement cryptography, and
no kernel module is involved. For that you need a real Linux host.

**A cheap VPS is the honest test** and it is what this project is actually for. Any provider,
smallest tier, Ubuntu LTS. Run the three scripts, add a client, import the config on your phone,
then check:

```bash
wg show                                  # handshake present, bytes moving?
curl -4 ifconfig.me                      # should report the server's IP, not yours
```

Then visit `dnsleaktest.com` on the client — resolvers should be the ones in `CLIENT_DNS`, not
your ISP's. See [DNS-LEAK-PREVENTION.md](DNS-LEAK-PREVENTION.md).

**A local VM works too** if you'd rather not pay: WSL2 with Ubuntu, or any hypervisor. You'll
get through installation, config generation and firewall rules. Full tunnel verification is
harder locally because NAT traversal and routing differ from a public host.

---

## What none of this covers

- Real cryptographic key exchange or handshakes.
- Kernel-level packet forwarding and NAT.
- Whether your provider filters UDP 51820.
- MTU problems, which usually show up as "connects fine, large transfers stall."
