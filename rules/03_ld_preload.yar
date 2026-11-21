import "elf"
rule Userland_LD_PRELOAD_Hiding_Heuristic {
 meta: category="userland_rootkit" confidence="medium" description="Shared ELF with preload and process or network hiding clues"
 strings:
  $pre1="/etc/ld.so.preload" ascii wide
  $pre2="LD_PRELOAD" ascii wide
  $pre3="/etc/ld.so.preload" xor(0x01-0xff)
  $pre4="LD_PRELOAD" base64
  $hide1="readdir64" ascii
  $hide2="/proc/net/tcp" ascii
  $hide3="/proc/net/udp" ascii
  $hide4="getdents64" ascii
 condition:
  uint32(0)==0x464c457f and elf.type==elf.ET_DYN and any of ($pre*) and 2 of ($hide*)
}
rule Loader_Config_Suspicious_Path {
 meta: category="loader_config" confidence="low" description="Preload configuration points to temporary or user-writable staging path; scan config content"
 strings:
  $p1="/tmp/" ascii
  $p2="/var/tmp/" ascii
  $p3="/dev/shm/" ascii
  $p4="/home/" ascii
 condition:
  filesize<65536 and uint32(0)!=0x464c457f and any of them
}
