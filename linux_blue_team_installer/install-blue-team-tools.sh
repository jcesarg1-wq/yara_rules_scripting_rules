#!/usr/bin/env bash
# Linux Blue Team tool installer: package-manager only, no curl | bash.
set -uo pipefail
PROFILE=core
DRY_RUN=0
ASSUME_YES=0
usage(){ cat <<'HELP'
Usage: sudo bash install-blue-team-tools.sh [--profile core|network|full] [--dry-run] [--yes]
  core: YARA, auditd, packet capture, process and ELF investigation
  network: core + tshark, Suricata, Zeek when packaged
  full: network + integrity, scanning, and advanced tracing tools
  --dry-run: show proposed package operations; do not install
  --yes: allow noninteractive installs (may accept package defaults)
Does not start services, change firewall, enable packet capture, or add repositories.
Unavailable packages are skipped and reported; installation is best effort.
HELP
}
while (($#)); do case "$1" in
 --profile) [[ $# -ge 2 ]] || { usage; exit 2; }; PROFILE="$2"; shift 2;;
 --dry-run) DRY_RUN=1; shift;;
 --yes) ASSUME_YES=1; shift;;
 -h|--help) usage; exit 0;;
 *) echo "Unknown argument: $1" >&2; usage; exit 2;;
esac; done
case "$PROFILE" in core|network|full) ;; *) echo "Invalid profile: $PROFILE" >&2; exit 2;; esac
if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then echo 'Run as root (sudo) for installation.' >&2; exit 1; fi
if [[ -r /etc/os-release ]]; then . /etc/os-release; fi
DISTRO="${PRETTY_NAME:-unknown}"
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
elif command -v pacman >/dev/null; then PM=pacman
elif command -v zypper >/dev/null; then PM=zypper
elif command -v apk >/dev/null; then PM=apk
else echo 'Unsupported package manager. Supported: apt, dnf, yum, pacman, zypper, apk.' >&2; exit 1; fi
printf 'Detected: %s | package manager: %s | profile: %s | dry-run: %s\n' "$DISTRO" "$PM" "$PROFILE" "$DRY_RUN"
# Logical tool -> candidate distro package names. Each tool installed separately.
packages(){
 local key="$1"
 case "$key:$PM" in
  yara:*) echo yara;;
  audit:apk) echo audit;; audit:*) echo audit;;
  tshark:apt|tshark:apk) echo tshark;; tshark:*) echo wireshark-cli tshark;;
  bpftool:apt) echo linux-tools-common bpftool;; bpftool:*) echo bpftool;;
  zeek:*) echo zeek;;
  suricata:*) echo suricata;;
  python:*) echo python3;;
  tcpdump:*) echo tcpdump;;
  lsof:*) echo lsof;;
  jq:*) echo jq;;
  file:*) echo file;;
  strings:*) echo binutils;;
  kmod:*) echo kmod;;
  iproute:*) echo iproute2;;
  procps:*) echo procps;;
  inotify:*) echo inotify-tools;;
  aide:*) echo aide;;
  clamav:*) echo clamav;;
  strace:*) echo strace;;
  psmisc:*) echo psmisc;;
  nftables:*) echo nftables;;
  *) return 1;;
 esac
}
# Some names differ among distros; package queries avoid blindly installing unknown names.
available(){ local p="$1"; case "$PM" in
 apt) apt-cache show "$p" >/dev/null 2>&1;;
 dnf) dnf -q list --available "$p" >/dev/null 2>&1 || rpm -q "$p" >/dev/null 2>&1;;
 yum) yum -q list available "$p" >/dev/null 2>&1 || rpm -q "$p" >/dev/null 2>&1;;
 pacman) pacman -Si "$p" >/dev/null 2>&1 || pacman -Q "$p" >/dev/null 2>&1;;
 zypper) zypper --non-interactive info "$p" >/dev/null 2>&1 || rpm -q "$p" >/dev/null 2>&1;;
 apk) apk search -x "$p" 2>/dev/null | grep -q . || apk info -e "$p" >/dev/null 2>&1;;
 esac; }
installed(){ local p="$1"; case "$PM" in
 apt) dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed';;
 dnf|yum|zypper) rpm -q "$p" >/dev/null 2>&1;;
 pacman) pacman -Q "$p" >/dev/null 2>&1;;
 apk) apk info -e "$p" >/dev/null 2>&1;; esac; }
install_one(){ local p="$1"; local -a cmd; case "$PM" in
 apt) cmd=(apt-get install); [[ $ASSUME_YES -eq 1 ]] && cmd+=(-y); cmd+=("$p");;
 dnf) cmd=(dnf install); [[ $ASSUME_YES -eq 1 ]] && cmd+=(-y); cmd+=("$p");;
 yum) cmd=(yum install); [[ $ASSUME_YES -eq 1 ]] && cmd+=(-y); cmd+=("$p");;
 pacman) cmd=(pacman -S --needed); [[ $ASSUME_YES -eq 1 ]] && cmd+=(--noconfirm); cmd+=("$p");;
 zypper) cmd=(zypper); [[ $ASSUME_YES -eq 1 ]] && cmd+=(--non-interactive); cmd+=(install "$p");;
 apk) cmd=(apk add); [[ $ASSUME_YES -eq 1 ]] && cmd+=(--no-interactive); cmd+=("$p");;
 esac
 if [[ $DRY_RUN -eq 1 ]]; then printf 'PLAN: '; printf '%q ' "${cmd[@]}"; printf '\n'; return 0; fi
 printf '\nInstalling %s...\n' "$p"; "${cmd[@]}"; }
if [[ "$PM" == apt ]]; then
 if [[ $DRY_RUN -eq 1 ]]; then echo 'PLAN: apt-get update'; else apt-get update || echo 'WARN: apt update failed; cached metadata may be stale.' >&2; fi
elif [[ "$PM" == pacman ]]; then
 echo 'NOTE: On Arch, refresh/upgrade the system before package installs to avoid partial upgrades (pacman -Syu).'
fi
core=(yara audit python tcpdump lsof jq file strings kmod iproute procps psmisc)
network=(tshark suricata zeek)
full=(bpftool inotify aide clamav strace nftables)
selected=("${core[@]}")
[[ "$PROFILE" == network || "$PROFILE" == full ]] && selected+=("${network[@]}")
[[ "$PROFILE" == full ]] && selected+=("${full[@]}")
failures=(); missing=(); installed_now=(); already=()
for key in "${selected[@]}"; do
 found=0
 for pkg in $(packages "$key"); do
  if installed "$pkg"; then echo "OK: $key ($pkg already installed)"; already+=("$key"); found=1; break; fi
  if available "$pkg"; then
   if install_one "$pkg"; then installed_now+=("$key:$pkg"); else failures+=("$key:$pkg"); fi
   found=1; break
  fi
 done
 if [[ $found -eq 0 ]]; then echo "SKIP: $key not available in enabled $PM repositories"; missing+=("$key"); fi
done
printf '\nSUMMARY: installed/planned=%s already=%s unavailable=%s failed=%s\n' "${#installed_now[@]}" "${#already[@]}" "${#missing[@]}" "${#failures[@]}"
printf 'Unavailable: %s\n' "${missing[*]:-none}"
printf 'Failed: %s\n' "${failures[*]:-none}"
echo 'Check tools: yara --version; auditctl -s; tcpdump --version; tshark --version; zeek --version; suricata --build-info'
echo 'No services were enabled or started by this script directly. Package post-install scripts may start services.'
[[ ${#failures[@]} -eq 0 ]] || exit 1
