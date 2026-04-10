// severity: suspicious
rule Behavior_AntiDebug_IsDebuggerPresent {
    meta:
        description = "Imports IsDebuggerPresent — basic API debugger detection"
    strings:
        $idbg = "IsDebuggerPresent" fullword ascii
        $crdb = "CheckRemoteDebuggerPresent" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_AntiDebug_NtQuery {
    meta:
        description = "Uses NtQueryInformationProcess to detect debugger via ProcessDebugPort"
    strings:
        $ntA = "NtQueryInformationProcess" fullword ascii
        $zwA = "ZwQueryInformationProcess" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_AntiDebug_DebuggerWindow {
    meta:
        description = "Searches for known debugger windows by class name"
    strings:
        $fw_a    = "FindWindowA" fullword ascii
        $fw_w    = "FindWindowW" fullword ascii
        $olly    = "OLLYDBG" ascii
        // x64dbg uses Qt — match both Qt5 and Qt6 window class names
        $x64dbg5 = "Qt5QWindowIcon" ascii
        $x64dbg6 = "Qt6QWindowIcon" ascii
        $windbg  = "WinDbgFrameClass" ascii
    condition:
        ($fw_a or $fw_w) and ($olly or $x64dbg5 or $x64dbg6 or $windbg)
}

// severity: suspicious
rule Behavior_AntiDebug_Timing {
    meta:
        description = "Timing-based debugger detection — RDTSC or performance counter abuse"
    strings:
        $rdtsc = { 0F 31 }
        $tickA = "GetTickCount" fullword ascii
        $tickB = "GetTickCount64" fullword ascii
        $perfA = "QueryPerformanceCounter" fullword ascii
    condition:
        $rdtsc or 2 of ($tickA, $tickB, $perfA)
}

// severity: suspicious
rule Behavior_AntiDebug_Heap {
    meta:
        description = "NtQueryObject or heap flag check — advanced anti-debug"
    strings:
        $ntqobj = "NtQueryObject" fullword ascii
        $rtlqhp = "RtlQueryHeapInformation" fullword ascii
        $blkinp = "BlockInput" fullword ascii
    condition:
        any of them
}
