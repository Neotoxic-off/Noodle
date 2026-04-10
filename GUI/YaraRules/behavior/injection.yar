// severity: dangerous
rule Behavior_Injection_RemoteThread {
    meta:
        description = "WriteProcessMemory + CreateRemoteThread — classic remote thread injection"
    strings:
        $wpm  = "WriteProcessMemory" fullword ascii
        $crt  = "CreateRemoteThread" fullword ascii
        $crtx = "CreateRemoteThreadEx" fullword ascii
    condition:
        $wpm and ($crt or $crtx)
}

// severity: dangerous
rule Behavior_Injection_SyscallThread {
    meta:
        description = "WriteProcessMemory + NtCreateThread / RtlCreateUserThread — stealthy thread injection"
    strings:
        $wpm  = "WriteProcessMemory" fullword ascii
        $rtct = "RtlCreateUserThread" fullword ascii
        $ntct = "NtCreateThread" fullword ascii
    condition:
        $wpm and ($rtct or $ntct)
}

// severity: dangerous
rule Behavior_Injection_APCQueue {
    meta:
        description = "WriteProcessMemory + QueueUserAPC — early-bird APC injection"
    strings:
        $wpm  = "WriteProcessMemory" fullword ascii
        $qapc = "QueueUserAPC" fullword ascii
    condition:
        $wpm and $qapc
}

// severity: dangerous
rule Behavior_Injection_NtWrite {
    meta:
        description = "NtWriteVirtualMemory — stealthy process injection via native API"
    strings:
        $ntwvm = "NtWriteVirtualMemory" fullword ascii
        $zwwvm = "ZwWriteVirtualMemory" fullword ascii
    condition:
        any of them
}

// severity: dangerous
rule Behavior_Injection_ProcessHollowing {
    meta:
        description = "NtUnmapViewOfSection + NtMapViewOfSection — process hollowing"
    strings:
        $unmap_nt = "NtUnmapViewOfSection" fullword ascii
        $unmap_zw = "ZwUnmapViewOfSection" fullword ascii
        $map_nt   = "NtMapViewOfSection" fullword ascii
        $map_zw   = "ZwMapViewOfSection" fullword ascii
    condition:
        ($unmap_nt or $unmap_zw) and ($map_nt or $map_zw)
}

// severity: suspicious
rule Behavior_Injection_RemoteAlloc {
    meta:
        description = "VirtualAllocEx + OpenProcess — preparing remote memory for injection"
    strings:
        $vaex = "VirtualAllocEx" fullword ascii
        $op   = "OpenProcess" fullword ascii
    condition:
        $vaex and $op
}

// severity: suspicious
rule Behavior_Injection_ThreadHijack {
    meta:
        description = "SetThreadContext + SuspendThread — thread context hijacking"
    strings:
        $stc = "SetThreadContext" fullword ascii
        $gtc = "GetThreadContext" fullword ascii
        $sus = "SuspendThread" fullword ascii
    condition:
        $stc and ($sus or $gtc)
}

// severity: suspicious
rule Behavior_Injection_Shellcode {
    meta:
        description = "VirtualAlloc + VirtualProtect — allocates and marks executable memory"
    strings:
        $va = "VirtualAlloc" fullword ascii
        $vp = "VirtualProtect" fullword ascii
    condition:
        $va and $vp
}

// severity: dangerous
rule Behavior_Injection_DllHijack {
    meta:
        description = "LoadLibrary + WriteProcessMemory — DLL injection"
    strings:
        $lla = "LoadLibraryA" fullword ascii
        $llw = "LoadLibraryW" fullword ascii
        $wpm = "WriteProcessMemory" fullword ascii
    condition:
        ($lla or $llw) and $wpm
}
