#!/bin/sh
# Linux Blue Team: read-only cross-distro triage. Run as root for fuller results.
set -u
umask 077
OUT=${1:-"./triage-$(hostname 2>/dev/null || echo host)-$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd)
run() { label=$1; shift; { printf '### %s\n' "$label"; "$@"; } > "$OUT/$label.txt" 2>&1 || :; }
shrun() { label=$1; shift; { printf '### %s\n' "$label"; sh -c "$1"; } > "$OUT/$label.txt" 2>&1 || :; }
run identity sh -c 'date -Is; id; uname -a; cat /etc/os-release; uptime; ps -p 1 -o comm= 2>/dev/null'
run interfaces sh -c 'ip -br addr; ip route; cat /etc/resolv.conf'
run sockets sh -c 'ss -tulpen; ss -tunap'
run processes ps auxww
run logins sh -c 'who; w; last -n 25 2>/dev/null'
run users sh -c "awk -F: '\$3==0 {print \$1,\$3,\$7}' /etc/passwd; getent group sudo; getent group wheel; getent group docker; getent group lxd"
run ssh sh -c 'grep -RInE "^(PermitRootLogin|PermitEmptyPasswords|PasswordAuthentication|AllowUsers|Include|Port|ForceCommand|AuthorizedKeysCommand)" /etc/ssh 2>/dev/null; command -v sshd >/dev/null && sshd -T 2>/dev/null | grep -Ei "permitrootlogin|permitemptypasswords|passwordauthentication|allowtcpforwarding|x11forwarding|port"'
run pam sh -c 'grep -RInE "pam_exec|expose_authtok|pam_permit|pam_succeed_if" /etc/pam.d 2>/dev/null'
run persistence sh -c 'grep -RInE "LD_PRELOAD|curl |wget |/dev/tcp|@reboot|NOPASSWD|pam_exec" /etc/cron* /etc/systemd/system /etc/init.d /etc/profile /etc/profile.d /etc/sudoers /etc/sudoers.d /etc/apt/apt.conf.d /etc/pam.d 2>/dev/null | head -n 500'
run recent sh -c 'find /etc /usr/local/bin /usr/local/sbin /opt -xdev -type f -mtime -7 -ls 2>/dev/null | head -n 500'
run suid sh -c 'find / -xdev -type f -perm -4000 -ls 2>/dev/null | head -n 400'
run preload sh -c 'if [ -e /etc/ld.so.preload ]; then ls -l /etc/ld.so.preload; cat /etc/ld.so.preload; fi; grep -RIn LD_PRELOAD /etc/systemd /etc/init.d /etc/profile.d 2>/dev/null | head -n 100'
run modules sh -c 'cat /proc/modules 2>/dev/null; ls /sys/module 2>/dev/null; find /etc/modules-load.d /etc/modprobe.d -maxdepth 2 -type f -ls 2>/dev/null'
run firewall sh -c 'command -v nft >/dev/null && nft list ruleset; command -v iptables >/dev/null && iptables -S; command -v ufw >/dev/null && ufw status; command -v firewall-cmd >/dev/null && firewall-cmd --list-all'
if command -v systemctl >/dev/null 2>&1 && [ "$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')" = systemd ]; then
  run services systemctl list-units --type=service --state=running --no-pager
  run failed systemctl --failed --no-pager
  run timers systemctl list-timers --all --no-pager
  run enabled systemctl list-unit-files --state=enabled --no-pager
  run journal journalctl --since '-2 hours' -n 350 --no-pager
elif command -v rc-status >/dev/null 2>&1; then
  run services rc-status -a
  run enabled rc-update show -v
  run logs sh -c 'tail -n 250 /var/log/messages /var/log/auth.log 2>/dev/null'
elif command -v /etc/init.d/cron >/dev/null 2>&1; then
  run services sh -c 'ls -l /etc/init.d; ps aux'
fi
if command -v logread >/dev/null 2>&1; then run logread logread; fi
if command -v auditctl >/dev/null 2>&1; then run audit-rules auditctl -l; fi
if command -v bpftool >/dev/null 2>&1; then run ebpf bpftool prog show; fi
if command -v dpkg >/dev/null 2>&1; then run packages sh -c 'dpkg -l | tail -n 150'; elif command -v rpm >/dev/null 2>&1; then run packages sh -c 'rpm -qa | tail -n 150'; elif command -v apk >/dev/null 2>&1; then run packages apk info -v; fi
# Optional YARA: RULES_DIR=/path/to/rules ./linux-triage.sh [output-dir]
if [ -n "${RULES_DIR:-}" ] && command -v yara >/dev/null 2>&1 && [ -d "$RULES_DIR" ]; then
  mkdir -p "$OUT/yara"
  for rule in "$RULES_DIR"/*.yar "$RULES_DIR"/*.yara; do
    [ -f "$rule" ] || continue
    name=$(basename "$rule")
    { for target in /etc/pam.d /etc/ssh /etc/systemd/system /etc/cron.d /etc/apt/apt.conf.d /usr/local/bin /usr/local/sbin; do
        [ -d "$target" ] && yara -r -w "$rule" "$target"
      done; } > "$OUT/yara/$name.txt" 2>&1 || :
  done
fi
(cd "$OUT" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; > SHA256SUMS)
printf 'Read-only triage completed: %s\nTreat output as sensitive; it may include command lines, tokens or configuration secrets.\n' "$OUT"
