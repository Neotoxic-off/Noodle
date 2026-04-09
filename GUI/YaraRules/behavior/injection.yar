// severity: dangerous
rule Behavior_Injection_ClassicRemote {
    meta:
        description = "WriteProcessMemory + CreateRemoteThread — classic code injection"
    strings:
        $wpm   = "WriteProcessMemory" fullword ascii
        $crt   = "CreateRemoteThread" fullword ascii
        $crtex = "CreateRemoteThreadEx" fullword ascii
        $rtct  = "RtlCreateUserThread" fullword ascii
        $ntct  = "NtCreateThread" fullword ascii
        $qapc  = "QueueUserAPC" fullword ascii
    condition:
        $wpm and any of ($crt, $crtex, $rtct, $ntct, $qapc)
}

// severity: dangerous
rule Behavior_Injection_NtWrite {
    meta:
        description = "NtWriteVirtualMemory — stealthy process injection"
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
        description = "VirtualAllocEx + OpenProcess — preparing injection target"
    strings:
        $vaex = "VirtualAllocEx" fullword ascii
        $vpex = "VirtualProtectEx" fullword ascii
        $op   = "OpenProcess" fullword ascii
        $rpm  = "ReadProcessMemory" fullword ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Injection_ThreadHijack {
    meta:
        description = "SetThreadContext + SuspendThread — thread hijacking injection"
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
        description = "VirtualAlloc + VirtualProtect — allocates executable memory (shellcode loader)"
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
        $rta = "GetProcAddress" fullword ascii
    condition:
        ($lla or $llw) and $wpm
}
