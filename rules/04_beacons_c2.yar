rule Linux_Beacon_Execution_Combination {
 meta: category="beacon" confidence="low" description="Networking and command execution indicators; does not identify confirmed C2"
 strings:
  $net1="connect(" ascii
  $net2="socket(" ascii
  $net3="https://" ascii
  $net4="http://" ascii
  $net5="getaddrinfo" ascii
  $exec1="/bin/sh" ascii wide
  $exec2="/bin/bash" ascii wide
  $exec3="execve" ascii
  $exec4="popen(" ascii
  $tim1="sleep(" ascii
  $tim2="usleep(" ascii
  $tim3="nanosleep" ascii
 condition:
  filesize<20MB and 2 of ($net*) and any of ($exec*) and any of ($tim*)
}
rule Linux_Download_Execute_Script {
 meta: category="beacon_or_dropper" confidence="medium" description="Text script combining remote fetch and shell execution"
 strings:
  $fetch1="curl " ascii nocase
  $fetch2="wget " ascii nocase
  $shell1="| bash" ascii
  $shell2="| sh" ascii
  $shell3="bash -c" ascii
  $shell4="sh -c" ascii
 condition:
  filesize<2MB and any of ($fetch*) and any of ($shell*)
}
rule Linux_Encoded_Command_With_Network {
 meta: category="beacon_or_dropper" confidence="low" description="Encoded shell command with network fetch indicators"
 strings:
  $enc1="base64 -d" ascii
  $enc2="base64 --decode" ascii
  $enc3="base64 -di" ascii
  $net1="curl " ascii
  $net2="wget " ascii
  $net3="/dev/tcp/" ascii
 condition:
  filesize<2MB and any of ($enc*) and any of ($net*)
}
