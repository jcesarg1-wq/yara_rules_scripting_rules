import "elf"
rule LKM_Syscall_Stealth_Combination {
 meta: category="kernel" confidence="medium" description="Kernel module with symbol resolution plus stealth or credential indicators"
 strings:
  $module1="vermagic=" ascii
  $module2="__this_module" ascii
  $lookup="kallsyms_lookup_name" ascii
  $syscall="sys_call_table" ascii
  $lookup_xor="kallsyms_lookup_name" xor(0x01-0xff)
  $lookup_b64="kallsyms_lookup_name" base64
  $hide1="list_del_init" ascii
  $hide2="kobject_del" ascii
  $cred1="commit_creds" ascii
  $cred2="prepare_creds" ascii
 condition:
  uint32(0)==0x464c457f and elf.type==elf.ET_REL and
  any of ($module*) and any of ($lookup,$syscall,$lookup_xor,$lookup_b64) and
  (any of ($hide*) or all of ($cred*))
}
rule LKM_x64_CR0_WP_Heuristic {
 meta: category="kernel" confidence="medium" description="x86-64 CR0 read, WP clear, CR0 write within nearby bytes"
 strings:
  $read={ 0F 20 C0 }
  $clear={ 48 25 FF FF FE FF }
  $write={ 0F 22 C0 }
 condition:
  uint32(0)==0x464c457f and elf.type==elf.ET_REL and
  for any i in (1..#read) : (for any j in (1..#clear) : (for any k in (1..#write) : (
    @clear[j]>@read[i] and @clear[j]-@read[i]<64 and @write[k]>@clear[j] and @write[k]-@clear[j]<64)))
}
rule LKM_Inline_Hook_And_Context {
 meta: category="kernel" confidence="low" description="Trampoline byte sequence and hooking symbols"
 strings:
  $jump={ 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
  $jump2={ 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 }
  $hook1="register_ftrace_function" ascii
  $hook2="ftrace_set_filter_ip" ascii
  $hook3="sys_call_table" ascii
 condition:
  uint32(0)==0x464c457f and elf.type==elf.ET_REL and any of ($jump*) and any of ($hook*)
}
