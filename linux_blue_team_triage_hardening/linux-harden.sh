#!/bin/sh
# Linux Blue Team: default audit only; narrowly scoped, reversible changes on --apply.
set -u
umask 077
MODE=${1:---audit}
case "$MODE" in --audit|--apply) ;; *) echo 'Usage: sudo sh linux-harden.sh [--audit|--apply]' >&2; exit 2;; esac
OUT=${HARDEN_OUT:-"./hardening-$(hostname 2>/dev/null || echo host)-$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd)
LOG="$OUT/report.txt"
log() { printf '%s\n' "$*" | tee -a "$LOG"; }
log "Mode=$MODE host=$(hostname) time=$(date -Is)"
log '=== UID 0 accounts ==='
awk -F: '$3==0 {print $1,$3,$7}' /etc/passwd | tee -a "$LOG"
log '=== Privileged groups ==='
for g in sudo wheel docker lxd; do getent group "$g" 2>/dev/null | tee -a "$LOG" || :; done
log '=== SSH effective settings ==='
if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|permitemptypasswords|passwordauthentication|x11forwarding|allowtcpforwarding|maxauthtries' | tee -a "$LOG" || :; fi
log '=== Suspicious authentication and persistence leads ==='
grep -RInE 'pam_exec|expose_authtok|NOPASSWD|LD_PRELOAD' /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/systemd/system /etc/init.d 2>/dev/null | head -n 120 | tee -a "$LOG" || :
log '=== Preload and filesystem ==='
[ ! -e /etc/ld.so.preload ] || ls -l /etc/ld.so.preload | tee -a "$LOG"
find /etc -xdev -type f -perm -0002 -ls 2>/dev/null | head -n 100 | tee -a "$LOG" || :
log '=== Running service listeners ==='
ss -lntup 2>/dev/null | tee -a "$LOG" || :
if [ "$MODE" = --audit ]; then
  log 'AUDIT ONLY: no system settings changed.'
  log 'To apply narrowly scoped sysctl protections after reviewing host role: sudo sh linux-harden.sh --apply'
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then log 'ERROR: --apply requires root'; exit 1; fi
if [ -d /etc/config ] && command -v uci >/dev/null 2>&1; then
  log 'OpenWRT detected: refusing automated changes to router.'; exit 1
fi
if [ -f /etc/sysctl.conf ] || [ -d /etc/sysctl.d ]; then
  mkdir -p /etc/sysctl.d
  TARGET=/etc/sysctl.d/90-blue-team-safe.conf
  if [ -e "$TARGET" ]; then cp -p "$TARGET" "$OUT/90-blue-team-safe.conf.before" || exit 1; fi
  cat > "$TARGET" <<'SYSCTL'
# Conservative, generally safe filesystem protections; no routing/firewall changes.
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL
  log "Wrote $TARGET (previous copy, if any, in $OUT)"
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -p "$TARGET" >> "$LOG" 2>&1 || log 'WARNING: sysctl apply failed; inspect report'
  fi
else
  log 'No sysctl configuration directory found; skipped.'
fi
log 'No SSH, firewall, PAM, users, web, databases, services, or package state modified.'
log 'Rollback: restore saved prior file if present, otherwise remove /etc/sysctl.d/90-blue-team-safe.conf, then sysctl --system (review other sysctl policies first).'
