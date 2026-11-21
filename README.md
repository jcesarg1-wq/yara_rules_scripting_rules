# Linux Blue Team: Independent YARA Rule Pack

**Authorized defensive analysis only.** All rules are heuristics, not malware verdicts. No automatic deletion, killing, or chmod. The existing `ir-collect.sh` is provided unchanged for optional manual evidence collection.

## Rules

| File | Target | Notes |
|---|---|---|
| `01_lkm_rootkits.yar` | on-disk ELF relocatable kernel modules | hooking, stealth, x86-64 CR0, trampoline |
| `02_ebpf.yar` | eBPF ELF objects | section strings plus multiple contextual indicators |
| `03_ld_preload.yar` | ELF shared objects / preload config | loader injection and hiding; generic path rule is noisy |
| `04_beacons_c2.yar` | ELF/script content | network + execution + timing, download-and-execute; **does not extract or confirm C2 IPs** |
| `05_persistence_configs.yar` | PAM, SSH, systemd, APT text | inspired by Acme Anvil competition incidents |
| `06_other_malware.yar` | other suspicious content | shellcode, SUID shell references, cron |
| `07_encoded_indicators.yar` | binary/text | XOR, Base64, UTF-16LE wide strings; multiple hits required |

## Installation (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install yara auditd python3 binutils kmod
```

Fedora/RHEL: `sudo dnf install yara audit python3 binutils kmod` (YARA availability may depend on repositories). Arch: `sudo pacman -S yara audit python binutils kmod`. Validate package names for your distro.

## Test each rule separately

```bash
yara -s rules/05_persistence_configs.yar tests/pam-hook.txt
yara -s rules/05_persistence_configs.yar tests/ssh-weak.conf
yara -s rules/04_beacons_c2.yar tests/beacon-demo.sh
yara -s rules/06_other_malware.yar tests/cron-demo.txt
for rule in rules/*.yar; do echo "Checking $rule"; yarac "$rule" /tmp/blue-team-test.yarc || break; done
```

`yarac` compiles rules; remove `/tmp/blue-team-test.yarc` afterward. Scan **one rule file at a time** to tune false positives. To scan all rules, run `yara -r rules/04_beacons_c2.yar /path/to/samples`; YARA CLI takes a rule file and target, not a rules directory. `-r` traverses targets recursively. Use `-s` to print matched strings. Do not scan all of `/proc`, `/sys`, or `/dev` recursively.

For compressed `.ko.xz`/`.ko.zst`, decompress to a secure working directory before YARA; YARA cannot parse compressed ELF automatically. Do not execute suspicious files. Kernel module signing, package ownership, `modinfo`, `readelf`, and hashes must supplement rule matches.

## C2 / beacon interpretation

YARA matches **strings or bytes**, not observed outbound connections. A hard-coded IP or domain may be an indicator but cannot be assumed to be C2. Use `ss -tunap`, `journalctl`, DNS logs, firewall logs, packet capture, and parent-process information to corroborate. For suspicious PIDs: `ps -fp PID; readlink /proc/PID/exe; ls -l /proc/PID/fd; ss -tunap`. Repeated callback timing needs network telemetry; a string `sleep(` does not prove beaconing.

## Auditd (separate from YARA)

Review `auditd-watch.rules` and remove watches for paths that do not exist. Install it as `/etc/audit/rules.d/90-blue-team.rules`, then `sudo augenrules --load`. Verify with `sudo auditctl -l`; investigate with `sudo ausearch -k pam_change -i` or `sudo ausearch -k module_activity -i`. Rules collect only **future** activity and may produce substantial logs. They do not automatically launch a YARA scan or guarantee a live PID is still present. Add an event dispatcher later only after testing and validating inputs.

## Existing collector

The included `ir-collect.sh` is the original uploaded collector, unchanged. It defaults to `/etc/yara/linux_hunt.yar`, not these split files. To choose a rule explicitly:

```bash
sudo IR_RULES="$PWD/rules/01_lkm_rootkits.yar" bash ./ir-collect.sh --scan /path/to/suspicious.ko
```

It only creates a case on a match. Its network snapshot is **not proof of C2**. For a matchless incident, gather evidence separately. Preserve timestamps and originals; avoid `chmod 000` on live system dependencies.

## Limits and validation status

The rules were authored for standard YARA 4.x syntax. YARA is not installed in the authoring environment, so **compilation and runtime matches have not been independently verified**. Run the `yarac` checks on your VM first. The ELF module may be unavailable in restricted builds. Legitimate security software can match hooking, eBPF, or network strings. Generic CR0/trampoline signatures are x86-64 only. No rule proves that kernel memory was patched, that a kworker name is fake, or that a module is trusted. Build module allowlists from verified packages and signed vendor inventories, not a `none of` YARA condition. Filesystem timestamps are not reliable proof of tampering without earlier audit/baseline records.
