#!/usr/bin/env bash
# Defensive incident collector. Run as root for complete process/audit evidence.
# Requires: yara (or yara64), sha256sum, python3; optional: auditd, ss, lsof.
set -euo pipefail
umask 077

RULES="${IR_RULES:-/etc/yara/linux_hunt.yar}"
OUT="${IR_OUT:-/var/log/yara-incidents}"
TARGET=""
PID=""
SERIAL=""
MODE=""
YARA_BIN="${YARA_BIN:-yara}"

usage() {
  cat <<'HELP'
Usage:
  ir-collect.sh --scan /path/to/file [--pid 1234] [--audit-serial 567]
  ir-collect.sh --process 1234 [--audit-serial 567]
  ir-collect.sh --scan /path/to/file --pid 1234 --audit-serial 567
  ir-collect.sh --help

Environment:
  IR_RULES=/etc/yara/linux_hunt.yar   YARA rules file
  IR_OUT=/var/log/yara-incidents       private evidence directory
  YARA_BIN=yara                        executable (or yara64 if installed)

Examples:
  sudo ./ir-collect.sh --scan /tmp/sample.ko
  sudo ./ir-collect.sh --scan /tmp/sample.so --pid 1234 --audit-serial 567
  sudo ./ir-collect.sh --process 1234
  yara --help                           YARA's own CLI help
  yara64 --help                         if that executable exists
  yara -s /etc/yara/linux_hunt.yar /tmp/sample.ko
  yara -s /etc/yara/linux_hunt.yar 1234  # scan process memory, permissions permitting

Behavior: scans ONCE per invocation, creates a case ONLY on a YARA match.
An audit dispatcher must call this script; audit rules alone do not invoke it.
HELP
}

while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --scan) (($# >= 2)) || { usage >&2; exit 2; }; MODE=file; TARGET="$2"; shift 2 ;;
    --process) (($# >= 2)) || { usage >&2; exit 2; }; MODE=process; PID="$2"; shift 2 ;;
    --pid) (($# >= 2)) || { usage >&2; exit 2; }; PID="$2"; shift 2 ;;
    --audit-serial) (($# >= 2)) || { usage >&2; exit 2; }; SERIAL="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$MODE" ]] || { usage >&2; exit 2; }
[[ -z "$PID" || "$PID" =~ ^[0-9]+$ ]] || { echo 'Invalid PID' >&2; exit 2; }
[[ -z "$SERIAL" || "$SERIAL" =~ ^[0-9]+$ ]] || { echo 'Invalid audit serial' >&2; exit 2; }
[[ -r "$RULES" ]] || { echo "Rules not readable: $RULES" >&2; exit 2; }
command -v "$YARA_BIN" >/dev/null || { echo "YARA executable missing: $YARA_BIN" >&2; exit 2; }
if [[ "$MODE" == file ]]; then
  [[ -f "$TARGET" && -r "$TARGET" ]] || { echo "File not readable: $TARGET" >&2; exit 2; }
  SCAN_TARGET="$TARGET"
else
  [[ -d "/proc/$PID" ]] || { echo "PID not present: $PID" >&2; exit 2; }
  SCAN_TARGET="$PID"
fi

# Do not trust filenames or YARA output as commands. All variables are quoted.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
if ! "$YARA_BIN" -s "$RULES" "$SCAN_TARGET" > "$TMP" 2> "${TMP}.err"; then
  cat "${TMP}.err" >&2
  rm -f "${TMP}.err"
  exit 1
fi
rm -f "${TMP}.err"
[[ -s "$TMP" ]] || { echo 'No YARA matches'; exit 0; }

mkdir -p -- "$OUT"
CASE=$(mktemp -d "$OUT/case-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
cp -- "$TMP" "$CASE/yara_matches.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$CASE/detected_utc.txt"
hostname -f > "$CASE/hostname.txt" 2>/dev/null || hostname > "$CASE/hostname.txt"
"$YARA_BIN" --version > "$CASE/yara_version.txt" 2>&1
sha256sum -- "$RULES" > "$CASE/rules_sha256.txt"
cp -- "$RULES" "$CASE/rules_snapshot.yar"
printf '%s\n' "$SERIAL" > "$CASE/audit_serial.txt"
printf '%s\n' "$MODE" > "$CASE/scan_mode.txt"
printf '%s\n' "$SCAN_TARGET" > "$CASE/scan_target.txt"

if [[ "$MODE" == file ]]; then
  sha256sum -- "$TARGET" > "$CASE/target_sha256.txt" || true
  stat -- "$TARGET" > "$CASE/target_stat.txt" || true
else
  echo 'Process memory scan: no single file hash represents scanned memory' > "$CASE/target_sha256.txt"
fi
if [[ -n "$PID" ]]; then
  ps -p "$PID" -o pid,ppid,uid,gid,user,lstart,etime,args > "$CASE/process.txt" 2>&1 || true
  readlink "/proc/$PID/exe" > "$CASE/executable.txt" 2>&1 || true
  if [[ -r "/proc/$PID/exe" ]]; then
    sha256sum "/proc/$PID/exe" > "$CASE/executable_sha256.txt" 2>&1 || true
  fi
  if [[ -r "/proc/$PID/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$PID/cmdline" > "$CASE/cmdline.txt" || true
  fi
  for f in maps smaps; do
    if [[ -r "/proc/$PID/$f" ]]; then
      cat "/proc/$PID/$f" > "$CASE/process_${f}.txt" 2>&1 || true
    fi
  done
  if command -v lsof >/dev/null; then
    lsof -nP -p "$PID" > "$CASE/open_files.txt" 2>&1 || true
  fi
fi
if command -v ss >/dev/null; then
  ss -tunap > "$CASE/network_snapshot.txt" 2>&1 || true
  # Snapshot only: endpoints are NOT verified malicious or necessarily owned by PID.
  ss -Htunap > "$CASE/network_raw.txt" 2>&1 || true
fi
if command -v ausearch >/dev/null; then
  if [[ -n "$SERIAL" ]]; then
    ausearch -a "$SERIAL" --raw > "$CASE/audit_raw.txt" 2>&1 || true
  elif [[ -n "$PID" ]]; then
    ausearch -p "$PID" -ts recent --raw > "$CASE/audit_recent_pid.txt" 2>&1 || true
  fi
fi
# Structured summary. Raw files remain the authoritative evidence.
CASE="$CASE" PID="$PID" SERIAL="$SERIAL" python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ['CASE'])
def read(name):
    f = p / name
    return f.read_text(errors='replace').strip() if f.exists() else None
report = {
    'classification': 'heuristic_match_not_confirmed_malware',
    'detected_utc': read('detected_utc.txt'),
    'hostname': read('hostname.txt'),
    'pid': int(os.environ['PID']) if os.environ['PID'] else None,
    'audit_serial': os.environ['SERIAL'] or None,
    'scan_mode': read('scan_mode.txt'),
    'scan_target': read('scan_target.txt'),
    'yara_version': read('yara_version.txt'),
    'yara_matches': read('yara_matches.txt'),
    'rule_file_sha256': read('rules_sha256.txt'),
    'target_sha256': read('target_sha256.txt'),
    'executable_sha256': read('executable_sha256.txt'),
    'process_snapshot': read('process.txt'),
    'network_evidence_file': 'network_snapshot.txt' if (p/'network_snapshot.txt').exists() else None,
    'remote_ip_assessment': 'unverified_endpoint_not_confirmed_C2',
    'memory_integrity_assessment': 'not_performed_yara_patterns_do_not_prove_tampering',
    'memory_maps_file': 'process_maps.txt' if (p/'process_maps.txt').exists() else None,
    'raw_audit_file': 'audit_raw.txt' if (p/'audit_raw.txt').exists() else None,
}
# Parse public IPs from ss snapshot as investigation leads, never as malware verdicts.
import ipaddress, re
endpoints = set()
for line in (read('network_raw.txt') or '').splitlines():
    # ss output: Netid State Recv-Q Send-Q Local Peer Process
    fields = line.split()
    if len(fields) < 6: continue
    peer = fields[5]
    match = re.match(r'^\[([^]]+)\]:(\d+)$', peer) or re.match(r'^([^:]+):(\d+)$', peer)
    if not match: continue
    try:
        addr = ipaddress.ip_address(match.group(1).split('%')[0])
        if addr.is_global:
            endpoints.add((str(addr), int(match.group(2))))
    except ValueError: pass
report['observed_public_endpoints'] = [dict(ip=ip, port=port, classification='unverified') for ip, port in sorted(endpoints)]
(p/'incident.json').write_text(json.dumps(report, indent=2) + '\n')
PY
( cd "$CASE" && sha256sum -- * > evidence_manifest.sha256 )
logger -t yara-incident "YARA heuristic match: case=$CASE pid=${PID:-unknown} audit_serial=${SERIAL:-unknown}" || true
printf 'MATCH: %s\n' "$CASE"
