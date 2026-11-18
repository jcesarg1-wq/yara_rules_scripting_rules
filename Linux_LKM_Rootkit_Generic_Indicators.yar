import "elf"

rule Linux_LKM_Rootkit_Generic_Indicators
{
    meta:
        description = "Detects suspicious Linux Kernel Module (LKM) rootkit behaviors, CR0 manipulation, and obfuscated hooks"
        author = "Security Analyst"
        target_entity = "Linux ELF / Kernel Object (.ko)"

    strings:
        // Kernel module identifiers
        $kmod1 = "vermagic=" ascii
        $kmod2 = "module_layout" ascii

        // Hooking and stealth symbols (including XOR/Base64 variants)
        $hook1 = "sys_call_table" ascii xor(0x01-0xff) base64
        $hook2 = "kallsyms_lookup_name" ascii xor(0x01-0xff) base64
        $hook3 = "commit_creds" ascii
        $hook4 = "prepare_creds" ascii

        // Self-hiding functions
        $hide1 = "list_del_init" ascii
        $hide2 = "kobject_del" ascii

        // x86_64 CR0 Write-Protection bypass opcodes (mov rax, cr0 ... mov cr0, rax)
        $cr0_bypass = { 0F 20 C0 [1-16] 0F 22 C0 }

        // Inline 64-bit trampoline hook (movabs rax, addr; jmp rax)
        $trampoline = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }

    condition:
        // Must be a valid ELF binary (0x7F 'ELF')
        uint32(0) == 0x464c457f and
        // Confirm it is a relocatable object file (ET_REL = 1, standard for .ko files)
        elf.type == elf.ET_REL and
        // Must contain standard kernel module metadata
        all of ($kmod*) and
        (
            // Either directly bypasses CR0 memory protections
            $cr0_bypass or
            // Or combines syscall hooking with credential manipulation or self-hiding
            (any of ($hook1, $hook2) and (all of ($hook3, $hook4) or any of ($hide*) or $trampoline))
        )
}
