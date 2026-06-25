#!/bin/sh
# scripts/host-hardening-audit.sh — READ-ONLY OpenBSD host hardening collector.
#
# Gathers the OS-level configuration needed for a hardening review. It makes NO
# changes: only reads config, perms, sysctls, and rule sets. Run as root so it
# can read sshd_config/doas.conf/pf rules:
#
#   doas sh scripts/host-hardening-audit.sh > /tmp/host-audit.txt 2>&1
#   # then paste /tmp/host-audit.txt back
#
# Safe to run repeatedly. Nothing here writes, restarts, or mutates state.

sec() { printf '\n========== %s ==========\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

sec "SYSTEM"
uname -a
sysctl kern.version 2>/dev/null | head -1
echo "securelevel: $(sysctl -n kern.securelevel 2>/dev/null)"
echo "--- syspatch (pending) ---"; syspatch -c 2>/dev/null || echo "(syspatch -c unavailable)"
echo "--- pkg_add updates available ---"; pkg_info -u 2>/dev/null | head -20 || true

sec "SECURITY SYSCTLS"
for k in kern.securelevel kern.nosuidcoredump kern.allowkmem kern.maxfiles \
         ddb.console ddb.panic machdep.allowaperture machdep.kbdreset \
         net.inet.ip.forwarding net.inet6.ip6.forwarding net.inet.ip.redirect \
         net.inet.tcp.always_keepalive net.inet.udp.checksum \
         hw.smt vm.malloc_conf; do
  printf '%-32s = %s\n' "$k" "$(sysctl -n $k 2>/dev/null || echo n/a)"
done

sec "ACCOUNTS / SHELLS"
echo "--- non-nologin/false shells (review any service acct with a real shell) ---"
awk -F: '$7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" {printf "%-16s uid=%-6s shell=%s\n",$1,$3,$7}' /etc/passwd
echo "--- uid 0 accounts (should be only root) ---"
awk -F: '$3==0 {print $1}' /etc/master.passwd 2>/dev/null || awk -F: '$3==0{print $1}' /etc/passwd
echo "--- empty-password accounts (should be none) ---"
awk -F: '($2=="" ) {print $1" HAS EMPTY PASSWORD"}' /etc/master.passwd 2>/dev/null || echo "(need root for master.passwd)"
echo "--- login.conf auth/limits (default + daemon classes) ---"
grep -E '^(default|daemon|staff|auth|:tc|:passwordcheck|:minpasswordlen|:umask)' /etc/login.conf 2>/dev/null | head -40

sec "DOAS"
echo "--- /etc/doas.conf ---"; cat /etc/doas.conf 2>/dev/null
ls -l /etc/doas.conf 2>/dev/null

sec "SSHD (effective config)"
if have sshd; then sshd -T 2>/dev/null | grep -Ei \
  'permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractive|challengeresponse|maxauthtries|maxsessions|logingracetime|x11forwarding|allowtcpforwarding|permittunnel|allowagentforwarding|ciphers|macs|kexalgorithms|hostkeyalgorithms|clientalive|allowusers|allowgroups|denyusers|gatewayports|permitemptypasswords|usedns|banner|loglevel' ; \
else echo "(sshd -T unavailable; dumping sshd_config)"; fi
echo "--- /etc/ssh/sshd_config (non-comment) ---"
grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null

sec "PF FIREWALL"
echo "--- pfctl -si (info) ---"; pfctl -si 2>/dev/null | head -20
echo "--- pfctl -sr (rules) ---"; pfctl -sr 2>/dev/null
echo "--- pfctl -sn (nat/rdr) ---"; pfctl -sn 2>/dev/null
echo "--- pfctl -s Tables ---"; pfctl -s Tables 2>/dev/null
echo "--- bruteforce table entries ---"; pfctl -t bruteforce -T show 2>/dev/null | head -40
echo "--- /etc/pf.conf (non-comment) ---"; grep -vE '^\s*#|^\s*$' /etc/pf.conf 2>/dev/null

sec "LISTENING SOCKETS"
netstat -ln -f inet 2>/dev/null
netstat -ln -f inet6 2>/dev/null
echo "--- unix admin sockets ---"; ls -l /var/spt-txn/sockets 2>/dev/null

sec "ENABLED SERVICES (attack surface)"
rcctl ls on 2>/dev/null
echo "--- rc.conf.local ---"; cat /etc/rc.conf.local 2>/dev/null

sec "RELAYD / HTTPD / TLS"
echo "--- /etc/relayd.conf (non-comment) ---"; grep -vE '^\s*#|^\s*$' /etc/relayd.conf 2>/dev/null
echo "--- /etc/httpd.conf (non-comment) ---"; grep -vE '^\s*#|^\s*$' /etc/httpd.conf 2>/dev/null
echo "--- acme-client.conf ---"; grep -vE '^\s*#|^\s*$' /etc/acme-client.conf 2>/dev/null
echo "--- TLS cert files ---"; ls -l /etc/ssl/foss* /etc/ssl/private/foss* 2>/dev/null

sec "FILE PERMISSIONS"
echo "--- /var/spt-txn tree (perms/owners) ---"; ls -laR /var/spt-txn 2>/dev/null | head -120
echo "--- world-writable files outside /tmp (sample) ---"
find / -xdev -type f -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null | head -40
echo "--- unexpected suid/sgid binaries (sample) ---"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -60

sec "MOUNTS (nosuid/nodev/noexec)"
mount 2>/dev/null
echo "--- /etc/fstab ---"; cat /etc/fstab 2>/dev/null

sec "CRON / SCHEDULED"
echo "--- root crontab ---"; crontab -l 2>/dev/null
ls -l /var/cron/tabs 2>/dev/null
echo "--- /etc/daily.local /weekly.local /monthly.local ---"; cat /etc/daily.local /etc/weekly.local /etc/monthly.local 2>/dev/null

sec "LOGGING / TIME"
echo "--- syslog.conf ---"; grep -vE '^\s*#|^\s*$' /etc/syslog.conf 2>/dev/null
echo "--- newsyslog.conf (spt + auth) ---"; grep -Ei 'spt|auth|secure|daemon' /etc/newsyslog.conf 2>/dev/null
echo "--- ntpd.conf ---"; grep -vE '^\s*#|^\s*$' /etc/ntpd.conf 2>/dev/null
echo "--- accounting on? ---"; ls -l /var/account/acct 2>/dev/null || echo "(process accounting not enabled)"

sec "DONE"
echo "Collected $(date). Read-only — no changes made."
