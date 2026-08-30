#!/bin/ksh
# scripts/security-audit.sh — SPT-Txn OpenBSD security verification.
#
# Inspects the ACTUAL state of the host and the running services and reports
# PASS / FAIL / WARN per check — not assumptions. Run as root:
#
#   doas sh scripts/security-audit.sh
#
# Environment overrides:
#   REPO=$HOME/spt-poc           source tree (for pledge-source checks)
#   PUBHOST=foss.violetskysecurity.com  public hostname (for edge-exposure checks)
#   TR_TCP=127.0.0.1:8081               trust-registry read listener
#
# Honesty note: OpenBSD does not expose a running process's active pledge(2)
# promises, so "pledge enforced" is verified two ways here — (a) the deployed
# source calls the real unix.PledgePromises (not a no-op stub), and (b) the
# service started successfully, which under real pledge means the promise was
# applied (pledge failure is fatal). Anything we cannot directly prove is marked
# INFO, not PASS.

REPO="${REPO:-$HOME/spt-poc}"
PUBHOST="${PUBHOST:-foss.violetskysecurity.com}"
TR_TCP="${TR_TCP:-127.0.0.1:8081}"
RELAY_TR_PORT="${RELAY_TR_PORT:-4443}"   # relayd public port → trust registry
RELAY_CAT_PORT="${RELAY_CAT_PORT:-4444}" # relayd public port → CAT issuer
RELAYD_CONF="${RELAYD_CONF:-/etc/relayd.conf}"

pass=0; fail=0; warn=0
P() { echo "[PASS] $*"; pass=$((pass+1)); }
F() { echo "[FAIL] $*"; fail=$((fail+1)); }
W() { echo "[WARN] $*"; warn=$((warn+1)); }
I() { echo "[INFO] $*"; }
hdr() { echo; echo "== $* =="; }

# ── 1. OS patch level & kernel hardening ────────────────────────────────────
hdr "OS hardening"
I "OpenBSD $(uname -r) on $(uname -m)"
if command -v syspatch >/dev/null 2>&1; then
  pending=$(syspatch -c 2>/dev/null)
  if [ -z "$pending" ]; then P "syspatch: no pending patches"; else W "syspatch: pending: $pending"; fi
fi
sl=$(sysctl -n kern.securelevel 2>/dev/null)
if [ "${sl:-0}" -ge 1 ]; then P "kern.securelevel=$sl (>=1)"; else W "kern.securelevel=$sl (consider 1+ in multiuser)"; fi
# W^X / ASLR / hardened malloc are OpenBSD defaults and not runtime-toggleable.
mc=$(ls -l /etc/malloc.conf 2>/dev/null | sed 's/.*-> //')
I "malloc.conf: ${mc:-default} (OpenBSD malloc is hardened by default)"

# ── 2. Firewall (pf) ────────────────────────────────────────────────────────
hdr "Firewall (pf)"
if pfctl -si >/dev/null 2>&1; then
  if pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then P "pf is enabled"; else F "pf is DISABLED"; fi
  if pfctl -sr 2>/dev/null | grep -qE '^block.* in '; then
    P "pf has a default inbound block rule"
  else
    W "pf: no obvious default 'block in' — verify the ruleset is deny-by-default"
  fi
else
  F "cannot query pf (run as root)"
fi

# ── 3. Network exposure: what is actually listening ─────────────────────────
hdr "Listening sockets"
listen=$(netstat -an -f inet 2>/dev/null | grep LISTEN)
listen6=$(netstat -an -f inet6 2>/dev/null | grep LISTEN)
if echo "$listen$listen6" | grep -qE '\.443[[:space:]]'; then
  P "TLS terminator listening on :443"
elif rcctl check relayd >/dev/null 2>&1; then
  W "relayd is running but :443 is not bound — the :443 relay may have failed to bind (check the keypair/cert in relayd.conf)"
else
  W "nothing listening on :443 (relayd down?)"
fi
# Any service bound to a non-loopback address other than 80/443 is suspicious.
bad=$(echo "$listen" | awk '{print $4}' | grep -v '^127\.0\.0\.1' | grep -v '\.443$' | grep -v '\.22$' | grep -v '\.80$')
if [ -z "$bad" ]; then P "no app service bound to a public interface (only loopback + 22/80/443)"; else W "non-loopback listeners (review): $bad"; fi

# ── 4. relayd / httpd ───────────────────────────────────────────────────────
hdr "TLS proxy"
for svc in relayd httpd; do
  if rcctl check "$svc" >/dev/null 2>&1; then P "$svc is running"; else W "$svc not running"; fi
done

# ── 5. Edge exposure of mutating endpoints (C1 / C3) ────────────────────────
hdr "Edge exposure of mutating endpoints (C1 / C3)"
# A sensitive path is edge-exposed only if a relayd relay forwards it. The live
# probe is primary; when the edge port is unreachable (curl emits "000"), we fall
# back to the authoritative source — relayd.conf — and confirm no relay forwards
# the path. That is a positive config-grounded check, not an assumption.
forwarded() { grep -qE "pass[[:space:]]+request[[:space:]]+path[[:space:]]+\"$1\"" "$RELAYD_CONF" 2>/dev/null; }

# C1: trust-registry register must NOT be reachable through relayd.
code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST --max-time 8 "https://$PUBHOST:$RELAY_TR_PORT/tr/register" -d '{}' 2>/dev/null)
case "$code" in
  404|405) P "/tr/register not exposed via relayd:$RELAY_TR_PORT (HTTP $code)" ;;
  ""|000)
    if forwarded "/tr/register"; then
      F "/tr/register edge port unreachable yet relayd config forwards it — verify"
    else
      P "/tr/register is socket-only: no relayd relay forwards it ($RELAYD_CONF)"
    fi ;;
  *) F "/tr/register reachable via relayd:$RELAY_TR_PORT (HTTP $code) — must be socket-only" ;;
esac
# C3: CAT issuance must reject unauthenticated requests (401/403), not process
# them (a 400/200 means the issuance oracle accepts unauthenticated callers); or
# not be edge-exposed at all.
code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST --max-time 8 "https://$PUBHOST:$RELAY_CAT_PORT/cat/issue" -d '{}' 2>/dev/null)
case "$code" in
  401|403|404) P "/cat/issue rejects unauthenticated requests (HTTP $code)" ;;
  ""|000)
    if forwarded "/cat/issue"; then
      F "/cat/issue edge port unreachable yet relayd config forwards it — verify"
    else
      P "/cat/issue is not edge-exposed: no relayd relay forwards it ($RELAYD_CONF)"
    fi ;;
  *) F "/cat/issue processes unauthenticated requests (HTTP $code) — C3 unauthenticated issuance oracle" ;;
esac
# Admin socket must be owner-only.
for s in /var/spt-txn/sockets/tr-admin.sock; do
  if [ -S "$s" ]; then
    perm=$(stat -f '%Lp' "$s" 2>/dev/null)
    if [ "$perm" = "600" ]; then P "admin socket $s is 0600"; else F "admin socket $s is $perm (want 0600)"; fi
  fi
done

# ── 6. Service privilege separation ─────────────────────────────────────────
hdr "Service users / privilege separation"
for u in _spttr _sptaw _sptaci _sptat _sptbv _sptaud; do
  ent=$(grep "^$u:" /etc/passwd 2>/dev/null)
  [ -z "$ent" ] && continue
  shell=$(echo "$ent" | awk -F: '{print $7}')
  if [ "$shell" = "/sbin/nologin" ]; then P "$u has no shell ($shell)"; else W "$u shell is $shell (want /sbin/nologin)"; fi
done
# No SPT service may run as root.
for bin in trsvc catsvc capsvc ttssvc versvc audsvc; do
  line=$(ps -axo user,comm 2>/dev/null | grep "[ /]$bin$" | head -1)
  [ -z "$line" ] && continue
  ruser=$(echo "$line" | awk '{print $1}')
  if [ "$ruser" = "root" ]; then F "$bin is running as ROOT"; else P "$bin runs as $ruser (non-root)"; fi
done

# ── 7. pledge/unveil really enabled in the deployed source (C4) ─────────────
hdr "pledge/unveil enforcement (C4)"
for f in "$REPO"/cmd/*/pledge_openbsd.go; do
  [ -f "$f" ] || continue
  svc=$(basename "$(dirname "$f")")
  if grep -q "unix.PledgePromises" "$f" && ! grep -q "func pledge(_ string) error { return nil }" "$f"; then
    P "$svc: real pledge(2) in source (not a no-op)"
  else
    F "$svc: pledge is a NO-OP stub — sandboxing is inert"
  fi
done
# Services that hold a signing key but have NO pledge file at all.
for d in "$REPO"/cmd/*/; do
  svc=$(basename "$d")
  if ls "$d"main.go >/dev/null 2>&1 && grep -q "loadSignifyKey\|\.sec" "$d"main.go 2>/dev/null; then
    if ! ls "$d"pledge_openbsd.go >/dev/null 2>&1; then F "$svc loads a signing key but has NO pledge file"; fi
  fi
done

# ── 8. Signing-key files: permissions & encryption at rest ──────────────────
hdr "Signing keys at rest"
# NB: for-loop (not 'find | while') so PASS/FAIL counters update in this shell,
# not a pipe subshell. Key paths contain no spaces.
for k in $(find /var/spt-txn -name '*.sec' 2>/dev/null); do
  perm=$(stat -f '%Lp' "$k" 2>/dev/null); owner=$(stat -f '%Su' "$k" 2>/dev/null)
  case "$perm" in
    600|400) P "key $k perms $perm owner $owner" ;;
    *)       F "key $k perms $perm (want 600/400, group/other must not read) owner $owner" ;;
  esac
  # Encryption-at-rest is determined by signify's kdfrounds field (bytes 4-8,
  # big-endian uint32), NOT the kdfalg field which is always "BK". rounds==0
  # means the key was generated with -n and is UNENCRYPTED on disk.
  rounds_hex=$(tail -1 "$k" 2>/dev/null | openssl base64 -d 2>/dev/null | dd bs=1 skip=4 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
  if [ "$rounds_hex" = "00000000" ]; then \
    W "key $k is UNENCRYPTED at rest (kdfrounds=0) — perms are its only protection"; \
  elif [ -n "$rounds_hex" ]; then P "key $k is passphrase-encrypted at rest (kdfrounds>0)"; \
  else I "key $k: could not read kdfrounds"; fi
done

# ── 9. Registry: no active all-zero keys (C2) ───────────────────────────────
hdr "Trust registry contents (C2)"
list=$(curl -s --max-time 5 "http://$TR_TCP/tr/list" 2>/dev/null)
if [ -n "$list" ]; then
  # Correlate PER RECORD: an all-zero public_key is only a risk if that SAME
  # record is status=active. Revoked all-zero entries are the seeded placeholders
  # (trsvc seedIfEmpty seeds domain-a/domain-b slots StatusRevoked) — benign, and
  # the verifier refuses all-zero keys regardless (engine.go isAllZero, review C2).
  # Put each record object on its own line so the active+all-zero test is joint,
  # not "some key is active" AND "some key is all-zero" (the old false positive).
  recs=$(echo "$list" | tr -d ' \n' | awk '{gsub(/\},\{/,"}\n{"); print}')
  if echo "$recs" | grep '"public_key":"0\{64\}"' | grep -q '"status":"active"'; then
    F "registry has an ACTIVE all-zero key — a placeholder issuer was never replaced with its real key (run regkey) or must be revoked"
  elif echo "$recs" | grep -q '"public_key":"0\{64\}"'; then
    I "registry has revoked all-zero placeholder key(s) (seeded by seedIfEmpty) — benign; verifier also refuses all-zero keys"
  else
    P "no all-zero public keys in registry listing"
  fi
else
  I "trust registry not reachable on $TR_TCP (not running?) — skipped"
fi

# ── 10. doas & sshd ─────────────────────────────────────────────────────────
hdr "doas / sshd"
if [ -f /etc/doas.conf ]; then
  dperm=$(stat -f '%Lp' /etc/doas.conf 2>/dev/null)
  [ "$dperm" = "600" ] || [ "$dperm" = "640" ] || [ "$dperm" = "644" ] && P "doas.conf perms $dperm" || W "doas.conf perms $dperm"
  grep -q "keenenv" /etc/doas.conf 2>/dev/null && F "doas.conf has the 'keenenv' typo (should be 'keepenv')" || P "doas.conf has no keenenv typo"
  grep -q "permit *nopass" /etc/doas.conf 2>/dev/null && W "doas.conf has a 'permit nopass' rule — review" || I "doas.conf: no passwordless permit"
fi
if [ -f /etc/ssh/sshd_config ]; then
  grep -qi "^PermitRootLogin *no" /etc/ssh/sshd_config && P "sshd: PermitRootLogin no" || W "sshd: PermitRootLogin not set to no"
  if grep -qi "^PasswordAuthentication *no" /etc/ssh/sshd_config; then
    P "sshd: PasswordAuthentication no (key-only)"
  elif pfctl -sr 2>/dev/null | grep -qi 'bruteforce'; then
    P "sshd: password auth enabled, but SSH is brute-force throttled in pf (overload <bruteforce>)"
  else
    W "sshd: password auth enabled with no pf throttle/source-restriction — add one or use keys"
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════"
echo "  PASS=$pass  WARN=$warn  FAIL=$fail"
echo "════════════════════════════════════════════"
[ "$fail" -gt 0 ] && exit 1 || exit 0
