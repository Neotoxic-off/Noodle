// severity: suspicious
rule Tool_Keygen {
    meta:
        description = "Software keygen / serial generator"
    strings:
        $kg1 = "keygen" ascii nocase fullword
        $kg2 = "key generator" ascii nocase
        $kg3 = "serial generator" ascii nocase
        $kg4 = "KeyGen" ascii nocase
        $kg5 = "License Generator" ascii nocase
        $kg6 = "Crack by" ascii nocase
        $kg7 = "Cracked by" ascii nocase
        $kg8 = "Patched by" ascii nocase
        $kg9 = "serial number" ascii nocase
        $kg10 = "registration code" ascii nocase
        $kg11 = "activation key" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule Tool_SoftwarePatch {
    meta:
        description = "Binary patch / nop-based software crack"
    strings:
        $pt1 = "patcher" ascii nocase fullword
        $pt2 = "patch.exe" ascii nocase
        $pt3 = "patched" ascii nocase fullword
        $pt4 = "nop_patch" ascii nocase
        $pt5 = "Patch by" ascii nocase
        $pt6 = "Make Backup" ascii nocase
        $pt7 = "backup original" ascii nocase
        $pt8 = "file patched" ascii nocase
        $api = "WriteFile" ascii
        $seek = "SetFilePointer" ascii
    condition:
        ($api and $seek and 2 of ($pt1, $pt2, $pt3, $pt4, $pt5, $pt6, $pt7, $pt8))
        or 3 of ($pt1, $pt2, $pt3, $pt4, $pt5, $pt6, $pt7, $pt8)
}

// severity: suspicious
rule Tool_Dumper {
    meta:
        description = "Process / PE memory dumper tool"
    strings:
        $dm1 = "pe_dump" ascii nocase
        $dm2 = "dumper" ascii nocase fullword
        $dm3 = "MiniDump" ascii nocase
        $dm4 = "MiniDumpWriteDump" ascii
        $dm5 = "process_dump" ascii nocase
        $dm6 = "PEDump" ascii nocase
        $dm7 = "hollowing" ascii nocase
    condition:
        2 of them
}
