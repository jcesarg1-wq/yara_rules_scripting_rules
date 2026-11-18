import "elf"

// Defensive heuristics. Rule names describe evidence, not malware identities.
// yara -s linux_hunt.yar file ; sudo yara -s linux_hunt.yar PID
// Process-memory scanning may match bytes in legitimate libraries/JIT code.

rule Linux_LKM_Syscall_Hook_Heuristic {
 meta:
  category = "kernel" severity = "high" rule_revision = "2026-11-17.2"
  description = "Relocatable ELF with multiple hooking or stealth indicators"
 strings:
  $module_a = "vermagic=" ascii
  $module_b = "__this_module" ascii
  $sys_a = "sys_call_table" ascii
  $sys_b = "kallsyms_lookup_name" ascii
  $sys_c = "sys_call_table" xor(0x01-0xff)
  $hide_a = "list_del_init" ascii
  $hide_b = "kobject_del" ascii
  $cred_a = "commit_creds" ascii
  $cred_b = "prepare_creds" ascii
 condition:
  uint32(0) == 0x464c457f and elf.type == elf.ET_REL and
  1 of ($module_*) and 1 of ($sys_*) and
  (1 of ($hide_*) or all of ($cred_*))
}

rule Linux_x64_CR0_Write_Protection_Heuristic {
 meta:
  category = "kernel" severity = "high" rule_revision = "2026-11-17.2"
  description = "Nearby CR0 read/write and WP-bit clear bytes; x86-64 only"
 strings:
  $read = { 0F 20 C0 }
  $write = { 0F 22 C0 }
  $clear_wp = { 48 25 FF FF FE FF }
 condition:
  uint32(0) == 0x464c457f and $clear_wp and
  for any i in (1..#read) : (
   for any j in (1..#write) : (
    @write[j] > @read[i] and @write[j] - @read[i] < 96
   )
  )
}

rule Linux_x64_Inline_Trampoline_Heuristic {
 meta:
  category = "memory_hook" severity = "medium" rule_revision = "2026-11-17.2"
  description = "Absolute jump trampoline with hooking context"
 strings:
  $jmp_a = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
  $jmp_b = { 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 }
  $jmp_c = { FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
  $context_a = "ftrace_set_filter_ip" ascii
  $context_b = "sys_call_table" ascii
  $context_c = "kallsyms_lookup_name" ascii
 condition:
  any of ($jmp_*) and any of ($context_*)
}

rule Linux_Memory_Potential_Inline_Hook {
 meta:
  category = "memory_hunting" severity = "low" rule_revision = "2026-11-17.2"
  description = "Generic x86-64 trampoline: common legitimate matches; triage only"
 strings:
  $trampoline_rax = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
  $trampoline_r11 = { 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 }
  $indirect_jump = { FF 25 ?? ?? ?? ?? }
 condition:
  any of ($trampoline_*) or $indirect_jump
}

rule Linux_Userland_LDPreload_Hiding_Heuristic {
 meta:
  category = "userland" severity = "medium" rule_revision = "2026-11-17.2"
  description = "Shared object with preload and hiding-related strings"
 strings:
  $pre_a = "/etc/ld.so.preload" ascii wide
  $pre_b = "LD_PRELOAD" ascii wide
  $pre_c = "/etc/ld.so.preload" xor(0x01-0xff)
  $pre_d = "LD_PRELOAD" base64
  $hide_a = "readdir64" ascii
  $hide_b = "getdents64" ascii
  $hide_c = "/proc/net/tcp" ascii
  $hide_d = "/proc/net/udp" ascii
 condition:
  uint32(0) == 0x464c457f and elf.type == elf.ET_DYN and
  any of ($pre_*) and 2 of ($hide_*)
}

rule Linux_eBPF_Probe_Combination_Heuristic {
 meta:
  category = "ebpf" severity = "low" rule_revision = "2026-11-17.2"
  description = "eBPF program labels plus kernel introspection helpers"
 strings:
  $probe_a = "kprobe/" ascii
  $probe_b = "kretprobe/" ascii
  $probe_c = "tracepoint/" ascii
  $probe_d = "fentry/" ascii
  $probe_e = "fexit/" ascii
  $ctx_a = "bpf_probe_read_kernel" ascii
  $ctx_b = "bpf_get_current_task" ascii
  $ctx_c = "bpf_get_current_pid_tgid" ascii
 condition:
  uint32(0) == 0x464c457f and elf.type == elf.ET_REL and
  any of ($probe_*) and 2 of ($ctx_*)
}

rule Linux_WebShell_PHP_Heuristic {
 meta:
  category = "webshell" severity = "medium" rule_revision = "2026-11-17.2"
  description = "PHP command execution plus request-controlled input"
 strings:
  $php = "<?php" ascii nocase
  $input_a = "$_POST[" ascii
  $input_b = "$_GET[" ascii
  $input_c = "$_REQUEST[" ascii
  $exec_a = "shell_exec(" ascii
  $exec_b = "system(" ascii
  $exec_c = "passthru(" ascii
  $exec_d = "proc_open(" ascii
  $exec_e = "eval(" ascii
  $decode_a = "base64_decode(" ascii
  $decode_b = "gzinflate(" ascii
 condition:
  filesize < 2MB and $php and any of ($input_*) and
  (2 of ($exec_*) or (1 of ($exec_*) and any of ($decode_*)))
}

rule Linux_WebShell_Python_Heuristic {
 meta:
  category = "webshell" severity = "medium" rule_revision = "2026-11-17.2"
  description = "Python HTTP request access and subprocess execution"
 strings:
  $request_a = "request.args" ascii
  $request_b = "request.form" ascii
  $request_c = "self.headers" ascii
  $exec_a = "subprocess.Popen(" ascii
  $exec_b = "subprocess.run(" ascii
  $exec_c = "os.popen(" ascii
  $exec_d = "os.system(" ascii
 condition:
  filesize < 2MB and any of ($request_*) and 1 of ($exec_*)
}

rule Linux_Beacon_Execution_Heuristic {
 meta:
  category = "beacon" severity = "medium" rule_revision = "2026-11-17.2"
  description = "Networking and command execution combined with persistence or evasion clues"
 strings:
  $net_a = "connect(" ascii
  $net_b = "getaddrinfo(" ascii
  $net_c = "curl_easy_perform" ascii
  $net_d = "socket.socket(" ascii
  $exec_a = "execve(" ascii
  $exec_b = "subprocess.Popen(" ascii
  $exec_c = "/bin/sh" ascii xor(0x01-0xff)
  $exec_d = "/bin/bash" ascii base64
  $persist_a = "@reboot" ascii
  $persist_b = "/etc/cron.d/" ascii
  $persist_c = "/etc/systemd/system/" ascii
  $persist_d = "LD_PRELOAD" ascii wide
 condition:
  filesize < 30MB and any of ($net_*) and any of ($exec_*) and any of ($persist_*)
}

rule Linux_Encoded_Loader_Heuristic {
 meta:
  category = "obfuscation" severity = "low" rule_revision = "2026-11-17.2"
  description = "Encoded loader and shell indicators; inspect before classifying"
 strings:
  $loader_a = "/etc/ld.so.preload" xor(0x01-0xff)
  $loader_b = "/etc/ld.so.preload" base64
  $loader_c = "LD_PRELOAD" wide ascii
  $shell_a = "/bin/sh" xor(0x01-0xff)
  $shell_b = "/bin/bash" base64
  $hide_a = "readdir64" ascii
  $hide_b = "getdents64" ascii
 condition:
  any of ($loader_*) and (any of ($shell_*) or any of ($hide_*))
}

rule Linux_Memory_Potential_Inline_Hook
{
  meta:
    description = "Potential x86-64 inline trampoline"
    severity = "medium"
    architecture = "x86_64"
    category = "memory_hunting"
    
  strings:
    // movabs rax, address; jmp rax
    $trampoline_rax = {
      48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0
    }
    
    // movabs r11, address; jmp r11
    $trampoline_r11 = {
      49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3
    }
    
    // RIP-relative indirect jump
    $indirect_jump = {
      FF 25 ?? ?? ?? ??
    }
    
  condition:
    $trampoline_rax or
    $trampoline_r11 or
    $indirect_jump
}