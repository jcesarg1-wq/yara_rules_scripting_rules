# Linux Blue Team: Triage + Safe Hardening

Designed for authorized competition defense, based on the Acme Underpressure exercise and the supplied Linux Blue Team manuals. Tested for shell syntax and a read-only smoke test in a Linux container; **not yet validated on all target distributions**.

## Files
- `linux-triage.sh`: read-only evidence collector for Debian/Ubuntu/Mint, Rocky/Fedora, Alpine/OpenRC, and lightweight OpenWRT environments (uses tools present). Optional independent YARA scans. Never removes or disables services.
- `linux-harden.sh`: default read-only security audit. `--apply` **only** writes two filesystem sysctl settings and applies them. Does not rotate passwords, disable users, edit SSH/PAM, touch firewall, or restart applications.

## Quick start
```sh
chmod +x linux-triage.sh linux-harden.sh
sudo ./linux-triage.sh /root/triage-first
sudo ./linux-harden.sh --audit
```

Optional YARA (rules must already be installed and compiled successfully):
```sh
sudo env RULES_DIR=/root/linux_yara_blue_team/rules ./linux-triage.sh /root/triage-yara
```

The YARA scan is scoped to high-value configuration and local executable directories, not entire disks. A hit is an investigation lead, not proof of malware. It will not automatically identify malicious kernel modules; scan module copies separately and decompress `.ko.xz`/`.ko.zst` first.

## Limited changes, with explicit consent
```sh
sudo ./linux-harden.sh --apply
```

The apply mode creates `/etc/sysctl.d/90-blue-team-safe.conf` with `fs.protected_hardlinks=1` and `fs.protected_symlinks=1`, then attempts to apply it. A prior file is backed up to the timestamped hardening output folder. **It is not a comprehensive hardening script.** If `/etc/config` and UCI are present, apply mode refuses to change OpenWRT.

Rollback: restore the prior copy if it existed, or remove `/etc/sysctl.d/90-blue-team-safe.conf` if newly created. Then review and reapply the intended sysctl configuration. Applying this file can still interact with other sysctl policies; review the host first.

## Distro compatibility
| Distro | Init | Tools used when present | Optional install |
|---|---|---|---|
| Debian/Ubuntu/Lubuntu/Mint | systemd | systemctl, journalctl, ss, ip, dpkg | `sudo apt update && sudo apt install iproute2 procps yara auditd tcpdump lsof` |
| Fedora/Rocky | systemd | systemctl, journalctl, ss, rpm | `sudo dnf install iproute procps-ng audit tcpdump lsof` (YARA may require additional repository) |
| Alpine | OpenRC | rc-status, rc-update, apk, logread/syslog | `sudo apk add iproute2 procps yara tcpdump lsof` (availability varies) |
| OpenWRT | procd | logread, UCI, process/network tools if present | Avoid bulk installation on router; package manager varies by release |

`auditd` does not automatically run these scripts; audit event integration requires a separate configured dispatcher. `journalctl` is normally part of systemd, not a separately installed tool.

## Critical cautions
1. Identify scored services, credentials, NAT and access routes before hardening.
2. Preserve working SSH/console access; don't blindly edit PAM, `sshd_config`, firewall or database binds.
3. Use `sshd -t`, `apache2ctl configtest`, `nginx -t` and service-specific health checks before reloading.
4. Review UID 0 users, authorized keys, cron/systemd/OpenRC persistence, `LD_PRELOAD`, SUID binaries and service overrides. Only remove confirmed unauthorized entries after preserving evidence and checking dependencies.
5. Output may contain sensitive information (command lines, logs, config paths). Keep under root-only directory and don't post raw reports publicly.
6. On a compromised host, on-host evidence can be tampered with. Prefer an external trusted collector when feasible.
7. Do not use these scripts as a substitute for application-specific hardening of Gitea, Samba, web servers, POS, ticketing apps or the router.

## Competition-first workflow
- Minute 0–3: identify host/OS, scored ports and access path; capture baseline.
- Minute 3–8: review UID 0, sudo, SSH keys, PAM, timers/cron, preload, listeners.
- Minute 8–15: make only confirmed, reversible changes; verify each service after each change.
- Later: optional YARA, targeted audit watches, network captures and forensic collection.
