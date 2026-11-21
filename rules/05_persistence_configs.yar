rule Competition_PAM_Exposed_Password_Hook {
 meta: category="pam" confidence="high" description="PAM exec hook exposing authentication token; verify authorization"
 strings:
  $a="pam_exec.so" ascii
  $b="expose_authtok" ascii
 condition:
  filesize<1MB and all of them
}
rule Competition_SSH_Weak_Settings {
 meta: category="ssh" confidence="medium" description="Weak SSH directives; scan SSH config only"
 strings:
  $a="PermitEmptyPasswords yes" ascii nocase
  $b="PermitRootLogin yes" ascii nocase
  $c="AllowTcpForwarding yes" ascii nocase
 condition:
  filesize<1MB and ($a or ($b and $c))
}
rule Competition_Systemd_Account_Recreation {
 meta: category="systemd" confidence="medium" description="Unit/script referencing recurring account privilege manipulation"
 strings:
  $a="useradd " ascii
  $b="usermod " ascii
  $c="chpasswd" ascii
  $d="NOPASSWD:" ascii
  $timer1="OnUnitActiveSec=" ascii
  $timer2="OnCalendar=" ascii
  $unit1="ExecStart=" ascii
  $unit2="/etc/sudoers.d/" ascii
 condition:
  filesize<1MB and any of ($a,$b,$c,$d) and any of ($timer*) or
  (filesize<1MB and any of ($a,$b,$c,$d) and any of ($unit*))
}
rule Competition_APT_Persistence_Hook {
 meta: category="apt" confidence="medium" description="APT hook and execution or download context"
 strings:
  $hook1="Pre-Invoke" ascii
  $hook2="Post-Invoke" ascii
  $exec1="curl " ascii
  $exec2="wget " ascii
  $exec3="/tmp/" ascii
  $exec4="/dev/shm/" ascii
 condition:
  filesize<1MB and any of ($hook*) and any of ($exec*)
}
