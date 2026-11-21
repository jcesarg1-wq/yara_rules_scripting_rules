# Linux Blue Team Package Installer

Installs defensive tools using the distribution's package manager, without fetching and executing remote install scripts. Supports apt (Debian/Ubuntu/Kali), dnf/yum (Fedora/RHEL-family), pacman (Arch), zypper (openSUSE), and apk (Alpine). Package availability varies by release and enabled repositories.

## Usage

```bash
bash install-blue-team-tools.sh --profile core --dry-run
sudo bash install-blue-team-tools.sh --profile core
sudo bash install-blue-team-tools.sh --profile network
sudo bash install-blue-team-tools.sh --profile full
```

`--yes` allows noninteractive package operations. Without it, package managers may prompt. Always inspect dry-run output first. `core` installs YARA, audit utilities, tcpdump, lsof, jq, binutils, kmod, and process/network basics. `network` adds tshark, Suricata, and Zeek if packaged. `full` adds bpftool, inotify-tools, AIDE, ClamAV, strace, and nftables.

**Important:** This installer does not configure audit rules, start network captures, enable IDS services, or modify the firewall. Package post-install scripts may start a service; review service state afterward. Zeek often requires an upstream repository and may be skipped; the script deliberately does not add third-party repositories. `journalctl` ships with systemd, not as a separate package on systemd distributions. Alpine commonly uses OpenRC and may not have journalctl. On Arch, upgrade consistently (`pacman -Syu`) before installation to avoid partial upgrades.

## Quick checks

```bash
yara --version
sudo auditctl -s
tcpdump --version
tshark --version
sudo ss -tunap
sudo journalctl -p warning -b -n 30
```

`auditctl` requires kernel audit support and privileges. For packet capture, use a bounded file and retain sensitive PCAP evidence securely. For example:

```bash
sudo timeout 60 tcpdump -i any -nn -s 0 -w /root/blue-team-60s.pcap
sudo tshark -r /root/blue-team-60s.pcap -q -z conv,ip
```

No detection tool alone proves that traffic is C2. Correlate destination, process, DNS, cadence, and host evidence. Avoid indiscriminate packet capture on networks you do not administer.
