
rule Linux_Kernel_Rootkit_Indicators
{
    meta:
        description = "ELF file with multiple kernel hooking or hiding indicators"
        category = "kernel-rootkit"
        confidence = "investigate"

    strings:
        $hook1 = "sys_call_table" ascii
        $hook2 = "kallsyms_lookup_name" ascii
        $hook3 = "ftrace_set_filter" ascii
        $hide1 = "getdents64" ascii
        $hide2 = "kill" ascii
        $hide3 = "proc_readdir" ascii

    condition:
        uint32(0) == 0x464c457f and
        2 of ($hook*) and
        1 of ($hide*)
}
