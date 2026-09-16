# DNS leak prevention

A DNS leak happens when a VPN tunnels regular traffic but the OS still sends DNS
lookups to the network's default resolver (typically the ISP or, on public
Wi-Fi, an untrusted one) outside the tunnel. That defeats the point of the VPN:
your ISP still sees every domain you visit.

## How this setup avoids it

1. **Full-tunnel routing.** Client configs set `AllowedIPs = 0.0.0.0/0`, so
   *all* traffic — including DNS — is routed through the WireGuard interface,
   not just traffic to the VPN subnet.
2. **Explicit DNS server.** Each client config sets
   `DNS = 1.1.1.1,1.0.0.1` (Cloudflare). WireGuard's client tools apply this to
   the OS resolver for as long as the tunnel is up, so lookups go out over the
   tunnel to a resolver you chose, not whatever the local network hands out via
   DHCP.
3. **No split tunneling.** Split-tunnel configs (`AllowedIPs` scoped to just the
   VPN subnet) are the most common cause of DNS leaks, since the OS falls back
   to its normal resolver for anything outside that range. This project
   intentionally defaults to full-tunnel.

## Verifying it

1. Connect to the VPN.
2. Visit https://dnsleaktest.com and run the extended test.
3. Every resolver listed should belong to Cloudflare (or whatever `CLIENT_DNS`
   was set to) — none should belong to your ISP or local network.

You can also check the OS resolver directly:

```bash
# Linux
resolvectl status wg0     # or: cat /etc/resolv.conf

# macOS
scutil --dns | grep -A 2 wg0

# Windows
nslookup example.com
```

## Changing the DNS resolver

Set `CLIENT_DNS` before provisioning a client, e.g. to use your own resolver or
Pi-hole instance running on the VPS:

```bash
CLIENT_DNS=10.8.0.1 sudo ./add-client.sh laptop
```
