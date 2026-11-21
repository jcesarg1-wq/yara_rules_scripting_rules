import "elf"
rule EBPF_Hooking_Stealth_Context {
 meta: category="ebpf" confidence="low" description="eBPF ELF with hooking and suspicious hiding/network context"
 strings:
  $section1="kprobe/" ascii
  $section2="tracepoint/" ascii
  $section3="fentry/" ascii
  $section4="xdp" ascii
  $hide1="getdents64" ascii
  $hide2="bpf_probe_write_user" ascii
  $hide3="/proc/net/tcp" ascii
  $hide4="/proc/net/udp" ascii
 condition:
  uint32(0)==0x464c457f and elf.type==elf.ET_REL and any of ($section*) and 2 of ($hide*)
}
