rule Encoded_Linux_Loader_Indicators {
 meta: category="encoded" confidence="low" description="Encoding-aware indicator combinations; not decryption or arbitrary XOR detection"
 strings:
  $pre_xor="/etc/ld.so.preload" xor(0x01-0xff)
  $pre_b64="/etc/ld.so.preload" base64
  $pre_wide="/etc/ld.so.preload" wide
  $shell_b64="/bin/bash" base64
  $shell_xor="/bin/bash" xor(0x01-0xff)
  $lookup_b64="kallsyms_lookup_name" base64
  $lookup_xor="kallsyms_lookup_name" xor(0x01-0xff)
 condition:
  filesize<20MB and 2 of them
}
