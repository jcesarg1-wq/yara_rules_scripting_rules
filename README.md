# Linux IR: YARA hunting + incident collector

## Files
- `linux_hunt.yar`: five independent heuristic YARA rules (LKM, CR0, trampoline, LD_PRELOAD, eBPF).
- `ir-collect.sh`: one-shot collector; no sleep or polling; creates a private case directory only on a match.

## Install (Ubuntu/Debian)
```bash
sudo apt install yara auditd python3 iproute2
sudo mkdir -p /etc/yara
sudo install -m 600 linux_hunt.yar /etc/yara/linux_hunt.yar
sudo install -m 700 ir-collect.sh /usr/local/sbin/ir-collect.sh
```

## Usage
```bash
ir-collect.sh --help
yara --help
yara --version
yara -s /etc/yara/linux_hunt.yar /path/to/suspicious.ko
sudo ir-collect.sh --scan /path/to/suspicious.ko
sudo ir-collect.sh --scan /path/to/suspicious.so --pid 1234 --audit-serial 567
sudo ir-collect.sh --process 1234
# If your installation provides a 'yara64' binary:
sudo YARA_BIN=yara64 ir-collect.sh --scan /path/to/suspicious.ko
```

`yara64` is a name used by some builds/distributions, not a universal Linux executable. Check `command -v yara64`. A PID scan may be blocked by kernel permissions and cannot be assumed to scan kernel memory.

## Audit event integration
Audit rules record events, but do **not** execute the collector. Build/configure a trusted audit dispatcher that parses complete event records, validates PID/paths, obtains the audit serial, and invokes `ir-collect.sh --scan PATH --pid PID --audit-serial SERIAL`. Do not execute untrusted audit record text in a shell. Some events (e.g. `init_module`) have no durable file path; `finit_module` may require file-descriptor-to-path correlation at event time. A process PID may be reused, and exited processes lose `/proc` data.

Example audit rules (adapt to your kernel and architecture):
```text
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_module_activity
-a always,exit -F arch=b64 -S bpf -k bpf_activity
-w /etc/modules-load.d/ -p wa -k module_persistence
-w /etc/modprobe.d/ -p wa -k modprobe_change
```
Apply using `sudo augenrules --load`. File watches require existing targets; directory watches do not automatically provide full historical contents.

## Evidence and caveats
Each match stores timestamps, hostname, rule snapshot and SHA-256, YARA version, raw matches, target SHA-256 (file scans), optional process PID/PPID/UID and executable hash, network snapshot, optional raw audit event, JSON summary, and manifest of evidence hashes. Hashes of collected files support later integrity checks but do not establish trusted chain of custody by themselves. Preserve the original artifact securely and forward evidence to a remote append-only log store where possible.

YARA rule names are heuristic categories, **not confirmed malware family names**. A jump opcode or eBPF helper name may be completely legitimate. Network snapshots are not proof of C2 or necessarily attributable to the alerted process. Static file YARA cannot establish that code has actually patched kernel memory. Auditd and `/proc` may be subverted after kernel compromise.

The script and rules were syntax-checked for Bash, but YARA compilation and end-to-end runtime were not tested in this environment; validate with `yara -w ...` and a harmless sample on your target system before deployment.

## Update 2026-11-17.2: web shells, beacons, memory hooks, endpoint evidence
The rule file now contains ten independent rules. Web-shell rules look for request-controlled command execution; beacon heuristics combine networking, execution, and persistence indicators. Neither proves maliciousness. Generic jump patterns, especially `FF 25`, are common in legitimate software. A YARA hit does **not** prove an illegal memory write, an injected jump, or a confirmed C2 IP.

The collector additionally captures `/proc/PID/maps` and `/proc/PID/smaps` (when readable) and lists **observed public endpoints** in `incident.json` as `unverified`. It cannot reliably associate all endpoints with the target PID, and `ss` is only a snapshot. Private/local addresses are excluded from that JSON endpoint list but retained in the raw network snapshot. IPs embedded in a sample are not extracted or classified by these rules; identifying true C2 requires independent network telemetry, reputation, and behavioral correlation.

### Memory dump and integrity investigation
`sudo yara -s linux_hunt.yar 1234` scans accessible process memory, not kernel memory and not a full dump. `sudo gcore -o /secure/incident-core 1234` can capture a user-process core (sensitive data; may pause process). Scan a core file using `yara -s linux_hunt.yar /secure/incident-core.1234`. Actual tamper detection requires trusted baseline comparison of mapped executable pages with relocation-aware handling, and corroborating telemetry (e.g. `mprotect`, `ptrace`, `process_vm_writev`, injected mappings). YARA does not compare trusted expected bytes with observed memory.

### Validation
Run `yara -w linux_hunt.yar /path/to/test` to compile and scan, or `yarac linux_hunt.yar compiled.yarc` to compile only (if installed). `yara --help`, `yara -s`, and `yara --version` show syntax, matched offsets, and engine version. Some installations use `yara64` instead of `yara`; check `command -v yara64`. `ir-collect.sh --help` documents the collector. Test against benign samples and tune false positives before enabling automatic alerts.
