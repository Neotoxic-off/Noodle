// severity: dangerous
rule Behavior_Privilege_TokenManipulation {
    meta:
        description = "Token privilege adjustment — privilege escalation or impersonation"
    strings:
        $adj  = "AdjustTokenPrivileges" fullword ascii
        $imp  = "ImpersonateLoggedOnUser" fullword ascii
        $lpvA = "LookupPrivilegeValueA" fullword ascii
        $lpvW = "LookupPrivilegeValueW" fullword ascii
        $opt  = "OpenProcessToken" fullword ascii
        $dup  = "DuplicateTokenEx" fullword ascii
    condition:
        2 of them
}

// severity: dangerous
rule Behavior_Privilege_UAC_Bypass {
    meta:
        description = "UAC bypass indicators — COM elevation or auto-elevated binary abuse"
    strings:
        $comev = "Elevation:Administrator!new:" ascii
        $uac1  = "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command" ascii
        $uac2  = "\\ComSpec" ascii
        $uac3  = "\\fodhelper.exe" ascii nocase
        $uac4  = "\\eventvwr.exe" ascii nocase
        $uac5  = "\\sdclt.exe" ascii nocase
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Privilege_NamedPipe {
    meta:
        description = "Named pipe impersonation — privilege escalation via pipe"
    strings:
        $crpipe = "CreateNamedPipeA" fullword ascii
        $crpipe2 = "CreateNamedPipeW" fullword ascii
        $imppipe = "ImpersonateNamedPipeClient" fullword ascii
    condition:
        $imppipe or ($crpipe and $crpipe2)
}
