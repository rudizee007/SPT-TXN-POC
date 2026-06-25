# Host-OS Hardening Review — foss.violetskysecurity.com (June 2026)

Read-only review of the OpenBSD 7.9 host that runs the SPT-Txn POC, based on a full
config collection (`scripts/host-hardening-audit.sh`, 2026-06-25). Complements the
application audit (`docs/SECURITY-AUDIT-2026-06.md`) and the deployment-posture script
(`scripts/security-audit.sh`). Nothing was changed; every fix below is proposed and
should be applied with review.

## Bottom line

The host is **well-built**: pf default-deny, `securelevel=1`, SMT disabled (side-channel),
`kern.allowkmem=0`, `ddb.console=0`, no IP forwarding, `PermitRootLogin no`, no empty
passwords, only `root` at uid 0, a modern PQ-capable SSH cipher/kex set, a minimal suid
set, correct 400/600 perms on signing keys, the admin socket at 0600, `nodev,nosuid` on
`/var`, `/home`, `/tmp`, and the relayd allow-list keeps `/tr/register` and `/cat/issue`
off the edge (C1/C3 holds at the proxy layer). No pending patches.

But there is **one High** and several **Medium** items — most are *stale attack surface*
and *missing TLS lifecycle/headers*, not broken controls.

## Findings summary

| ID | Severity | Area | Title |
|----|----------|------|-------|
| H1 | **High** | TLS key | TLS private key is world-writable (`/etc/ssl/letsencrypt/private/…key`) |
| HM1 | **Medium** | pf | Firewall opens world-facing ports with no listener (incl. stale 4443/4444) |
| HM2 | Medium | TLS | Let's Encrypt renewal not automated; certs will expire and break TLS |
| HM3 | Medium | relayd | No HSTS / security response headers on the public site |
| HM4 | Medium | sshd | No `AllowUsers`, TCP/agent forwarding on, high MaxAuthTries/grace, no idle timeout, SHA-1 MACs |
| HM5 | Medium | pf | No `scrub` / `antispoof` normalization |
| HL1 | Low | doas | `permit nopass keepenv root as root` is vestigial/keepenv |
| HL2 | Low | services | Unneeded daemons enabled: `sndiod`, `slowcgi`, `slaacd` |
| HL3 | Low | mounts | `wxallowed` on `/usr/local` and `/tmp`; `/usr/local` lacks `nosuid` |
| HL4 | Low | sysctl/misc | `net.inet.ip.redirect=1`; no process accounting; local-only logging |
| HL5 | Low | accounts | `build` (uid 21) has a login shell; consider `securelevel=2` |

---

## High

### H1 — TLS private key is world-writable
**Observed:** `find` flagged `/etc/ssl/letsencrypt/private/foss.violetskysecurity.com.key`
as world-writable (mode includes `o+w`). relayd serves TLS from
`/etc/ssl/private/foss.violetskysecurity.com.key` → `…/letsencrypt/live/…/privkey.pem`.

**Risk:** Any local account (including a compromised service user) can **overwrite the
server's TLS private key** — swap it for an attacker key, enabling MITM/impersonation of
the site, or simply break TLS. A private key should never be group- or world-writable.

**Fix (apply with review):**
```sh
# lock the offending file and the private dirs
doas chmod 600 /etc/ssl/letsencrypt/private/foss.violetskysecurity.com.key
doas chown root:wheel /etc/ssl/letsencrypt/private/foss.violetskysecurity.com.key
doas chmod 700 /etc/ssl/letsencrypt/private /etc/ssl/private
doas chmod 600 /etc/letsencrypt/live/foss.violetskysecurity.com/privkey.pem 2>/dev/null
# confirm none remain
find /etc/ssl /etc/letsencrypt -type f -perm -0002 2>/dev/null
```
Then verify which key relayd actually loads and that it is 600/root, and check whether the
world-writable file is the live key or a stray copy (delete the copy if stray).

---

## Medium

### HM1 — Firewall opens world-facing ports with nothing behind them (incl. stale 4443/4444)
**Observed:** `pf.conf` passes **inbound** from `any` to `tcp_pass = {53 80 443 123 465
4443 4444 4445}`. But `netstat -ln` shows the only public listeners are `:22`, `:80`,
`:443`, `:4445`. **Nothing listens on the inbound TCP holes 53, 123, 465, 4443, 4444.**
The `4443`/`4444` are exactly the old Travel-Rule ports the C1/C3 review said to retire —
relayd moved to `:4445`, but the firewall was never tightened. (Note: `udp_pass = {53 110
123 631}` is used only in a `pass out` rule — that's **egress**, not inbound exposure;
110/631 outbound are odd but low-risk egress hygiene, not open ports.)

**Risk:** Open world-facing inbound ports with no service behind them are needless attack
surface (scan noise, future-service exposure), and 4443/4444 directly contradict the C1/C3
remediation.

**Fix:** tighten to only what is served, then reload:
```
tcp_pass  = "{ 80 443 4445 }"
ssh_ports = "{ 22 31415 }"
udp_pass  = "{ }"            # nothing inbound UDP is served; drop the line's pass rule
tcp_out   = "{ 22 53 80 443 123 465 }"   # egress: DNS, NTP, ACME/patches, SSH; drop 4443/4444/31415 if unused
```
```sh
doas pfctl -nf /etc/pf.conf   # syntax check first (no apply)
doas pfctl -f  /etc/pf.conf   # apply
```
Keep `:80` (ACME + redirect), `:443` (site), `:4445` (Travel Rule API), `:22`/`:31415`
(SSH). Removing 4443/4444 finally closes the C1/C3 surface at the firewall.

### HM2 — Let's Encrypt renewal is not automated
**Observed:** certs are certbot-managed (`/etc/letsencrypt/live/…`), but the root crontab
has **no renewal job**, `/etc/daily.local` is empty, and `acme-client.conf` is empty
(native acme-client is not used). relayd loads the cert once at start and is not reloaded
on renewal.

**Risk:** Certs expire ~90 days after issue; with no automated `certbot renew` and no
relayd reload, **TLS will silently break** when they lapse — taking down both the site
(`:443`) and the Travel Rule API (`:4445`).

**Fix:** add a renewal + reload job (native `acme-client` is the lighter OpenBSD-idiomatic
option, but keeping certbot is fine):
```sh
# root crontab — renew daily at a low-traffic hour, reload relayd only if renewed
17 4 * * * certbot renew --quiet --deploy-hook "rcctl reload relayd"
```
Confirm a successful dry run: `doas certbot renew --dry-run`.

### HM3 — No HSTS / security headers on the public site
**Observed:** the relayd `spt_https` protocol sets `X-Forwarded-*` but adds no response
security headers.

**Risk:** No HSTS (downgrade/SSL-strip exposure), no `X-Content-Type-Options`,
`X-Frame-Options`/CSP (clickjacking/MIME-sniffing). Low exploitability for a static site,
but standard hardening and a good look for a security vendor's public surface.

**Fix:** in `protocol "spt_https"`:
```
match response header set "Strict-Transport-Security" value "max-age=31536000; includeSubDomains"
match response header set "X-Content-Type-Options" value "nosniff"
match response header set "X-Frame-Options" value "DENY"
match response header set "Referrer-Policy" value "no-referrer"
```
(Only enable HSTS once you're confident TLS won't lapse — see HM2.)

### HM4 — sshd hardening gaps
**Observed:** `passwordauthentication yes` + `kbdinteractiveauthentication yes`, no
`AllowUsers`/`AllowGroups` (any account may SSH), `allowtcpforwarding yes` +
`allowagentforwarding yes`, `maxauthtries 6`, `logingracetime 120`,
`clientaliveinterval 0` (idle sessions never expire), and the MAC list still includes
SHA-1 (`hmac-sha1-etm`, `hmac-sha1`). PermitRootLogin is correctly `no`.

**Risk:** Broader login/forwarding surface than needed; SHA-1 MACs are deprecated; no idle
timeout. Password auth + the pf throttle is also what keeps locking you out during deploys.

**Fix (`/etc/ssh/sshd_config`, then `rcctl reload sshd`):**
```
AllowUsers tarzan
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
KbdInteractiveAuthentication no
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
```
Best paired with adding an **SSH key** for `tarzan` (you can keep `PasswordAuthentication
yes` per your constraint — the key just stops the repeated password attempts that trip the
pf `<bruteforce>` table during deploys). `ssh-keygen -t ed25519` on the Mac →
`ssh-copy-id`, then test before relying on it.

### HM5 — pf has no scrub / antispoof
**Observed:** `pf.conf` has `set skip on lo` and the rules, but no traffic normalization or
antispoof.

**Risk:** Misses standard OpenBSD packet normalization (fragment reassembly, sanity) and
spoofed-source protection on the interface.

**Fix (near the top of `pf.conf`, before the pass rules):**
```
match in all scrub (no-df random-id reassemble tcp)
antispoof quick for { lo0 vio0 }
```
`pfctl -nf /etc/pf.conf` to validate before applying.

---

## Low (condensed)

- **HL1 — doas `permit nopass keepenv root as root`.** Root→root is low risk, but `keepenv`
  is discouraged (env-passing) and the rule looks vestigial. Remove it unless a specific
  root-run script needs passwordless doas; if it does, scope it to that command without
  `keepenv`. Keep `permit tarzan` (password-gated).
- **HL2 — trim enabled daemons.** `sndiod` (audio — pointless on a server), `slowcgi`
  (httpd.conf defines no CGI), and `slaacd` (IPv6 autoconf — disable if you don't use v6;
  also drop the `tcp6`/v6 listeners then) are unnecessary surface. `doas rcctl disable
  sndiod slowcgi` (and `slaacd` if v6 unused), then stop them.
- **HL3 — mount flags.** `/usr/local` and `/tmp` are `wxallowed` (permits W^X mappings);
  Go binaries don't need it — if no installed port requires W^X, remove `wxallowed` and add
  `nosuid` to `/usr/local` in `/etc/fstab`. Test after remount; some ports (browsers/JITs)
  need it, so verify first.
- **HL4 — misc.** `net.inet.ip.redirect=1` → set `0` (ignore ICMP redirects) in
  `/etc/sysctl.conf`; consider enabling process accounting (`accton /var/account/acct`) for
  forensics; consider shipping `auth`/`daemon` logs to an append-only/remote collector for
  tamper-evidence (the app audit's AUD-1 covers the Merkle log; OS logs are local-only).
- **HL5 — accounts / securelevel.** `build` (uid 21) has `/bin/ksh`; if you don't compile
  on this host, lock it (`usermod -s /sbin/nologin build`). Consider raising
  `kern.securelevel=2` (in `rc.securelevel`) for immutable pf rules + locked time — but
  only after confirming nothing needs to rewrite pf/relayd post-boot (the hourly
  `pfctl -t bruteforce -T expire` table op is still allowed at securelevel 2).

---

## Verified-good (assurance)

- **Kernel/sysctl:** `securelevel=1`, `nosuidcoredump=1`, `allowkmem=0`, `ddb.console=0`,
  `allowaperture=0`, `hw.smt=0` (side-channel mitigation), no IPv4/IPv6 forwarding.
- **Accounts:** only `root` at uid 0; no empty passwords; `PermitRootLogin no`.
- **SSH crypto:** modern, post-quantum-capable kex (`mlkem768x25519`, `sntrup761x25519`),
  AEAD ciphers (chacha20-poly1305, aes-gcm), Ed25519 host keys.
- **pf:** default `block all` + `block return`; SSH rate-limit → `<bruteforce>` overload with
  hourly expiry via cron; X11 (6000:6010) blocked; `_pbuild` egress blocked.
- **Secrets & perms:** `ct-issuer.sec` 400 `_sptaw`, other `.sec` 600 root/`_spttr`; admin
  socket 0600; `/var`,`/home`,`/tmp` mounted `nodev,nosuid`; suid set is just
  `ping`/`ping6`/`shutdown` (minimal).
- **Edge:** relayd allow-lists only `/travel/{verify,health}` + `/trp/transfer` on `:4445`,
  and `/tr/register` + `/cat/issue` are not edge-forwarded (C1/C3 holds at the proxy);
  HTTP→HTTPS 301; internal services bound to loopback only.
- **Ops:** no pending syspatches; `library_aslr` on; authenticated NTP constraints (quad9 /
  cloudflare) to prevent time-based attacks.

## Recommended order

1. **H1** — lock the TLS private key (one command; do this first).
2. **HM2** — automate cert renewal + relayd reload (prevents an imminent outage).
3. **HM1** — tighten pf to `{80 443 4445}` + SSH ports; finally closes the C1/C3 4443/4444 holes.
4. **HM4 + SSH key** — sshd hardening; the key also ends the deploy lockouts.
5. **HM5, HM3** — pf scrub/antispoof; HSTS/security headers (HSTS after renewal is solid).
6. **HL1–HL5** — sweep at leisure.

None of these is a remotely-exploitable RCE or an auth bypass; H1 is the one that warrants
prompt action (local TLS-key tamper), and HM2 is the one that will bite on a clock
(cert expiry) if left alone.
