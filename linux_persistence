
rule Linux_PAM_Suspicious_Exec
{
    meta:
        description = "PAM configuration invoking an unusual password hook"
        category = "persistence"

    strings:
        $pam = "pam_exec.so" ascii
        $token = "expose_authtok" ascii
        $path = "/usr/share/locale/en/unicode.so" ascii

    condition:
        all of them
}

rule Linux_Systemd_Account_Recreation
{
    meta:
        description = "Systemd timer associated with recurring account persistence"

    strings:
        $name = "user-account-helper" ascii
        $interval = "OnUnitActiveSec=60s" ascii
        $description = "Re-assert service accounts" ascii

    condition:
        $name and ($interval or $description)
}

rule Linux_SSH_Weak_Configuration
{
    meta:
        description = "Potentially dangerous SSH authentication settings"

    strings:
        $empty = /PermitEmptyPasswords[ \t]+yes/ nocase
        $root = /PermitRootLogin[ \t]+yes/ nocase
        $forward = /AllowTcpForwarding[ \t]+yes/ nocase

    condition:
        $empty or ($root and $forward)
}

rule Linux_Persistence_Library_Preload
{
    meta:
        description = "Possible dynamic library preload persistence"

    strings:
        $preload = "LD_PRELOAD" ascii
        $config = "/etc/ld.so.preload" ascii
        $library = ".so" ascii

    condition:
        ($preload or $config) and $library
}
