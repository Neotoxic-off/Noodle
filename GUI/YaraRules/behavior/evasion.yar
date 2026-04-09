// severity: suspicious
rule Behavior_Evasion_VMDetect {
    meta:
        description = "Virtual machine detection strings or registry checks"
    strings:
        $vbox1  = "VBoxGuest" ascii nocase
        $vbox2  = "VBOXSVGA" ascii nocase
        $vbox3  = "VirtualBox" ascii nocase
        $vmware1 = "VMware" ascii nocase
        $vmware2 = "vmtoolsd" ascii nocase
        $qemu1  = "QEMU" ascii nocase
        $qemu2  = "qemu-ga" ascii nocase
        $hyper1 = "Hyper-V" ascii nocase
        $xen1   = "XenService" ascii
        $kvm1   = "VMMEMCTL" ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Evasion_SandboxArtifacts {
    meta:
        description = "Sandbox detection — known analysis tool names or registry keys"
    strings:
        $cuckoo  = "cuckoo" ascii nocase
        $anyrun  = "any.run" ascii nocase
        $wireshark = "wireshark" ascii nocase
        $procmon = "procmon" ascii nocase
        $fiddler = "fiddler" ascii nocase
        $ida     = "ida.exe" ascii nocase
        $x64dbg  = "x64dbg.exe" ascii nocase
        $olly    = "ollydbg.exe" ascii nocase
        $ghidra  = "ghidra" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Evasion_SleepDelay {
    meta:
        description = "Sleep or delay calls — sandbox evasion by waiting out analysis window"
    strings:
        $sleepA  = "Sleep" fullword ascii
        $sleepEx = "SleepEx" fullword ascii
        $waitObj = "WaitForSingleObject" fullword ascii
        $ntdelay = "NtDelayExecution" fullword ascii
    condition:
        2 of them
}

// severity: dangerous
rule Behavior_Evasion_AMSI_Bypass {
    meta:
        description = "AMSI bypass — patches AmsiScanBuffer or unloads amsi.dll"
    strings:
        $amsi1  = "AmsiScanBuffer" ascii
        $amsi2  = "amsi.dll" ascii nocase
        $amsi3  = "AmsiInitialize" ascii
        $amsi4  = "AmsiOpenSession" ascii
    condition:
        2 of them
}

// severity: dangerous
rule Behavior_Evasion_ETW_Patch {
    meta:
        description = "ETW (Event Tracing for Windows) patching — disables logging"
    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "EtwNotificationRegister" ascii
        $etw3 = "NtTraceEvent" ascii
        $ntdll = "ntdll.dll" ascii nocase
    condition:
        $etw1 or $etw2 or $etw3
}
