// severity: suspicious
rule Lang_PowerShell_Compiled {
    meta:
        description = "PowerShell script compiled to executable (PS2EXE, Invoke-PS2EXE)"
    strings:
        $ps2exe  = "PS2EXE" ascii
        $psexe2  = "ps2exe" ascii nocase
        $pshost  = "PowerShell" ascii
        $psrun   = "System.Management.Automation" ascii
        $psdll   = "System.Management.Automation.dll" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule Lang_PowerShell_Encoded {
    meta:
        description = "Binary contains encoded or obfuscated PowerShell commands"
    strings:
        $enc1   = "powershell -enc" nocase ascii
        $enc2   = "powershell -e " nocase ascii
        $enc3   = "powershell -EncodedCommand" nocase ascii
        $bypass = "-ExecutionPolicy Bypass" nocase ascii
        $hidden = "-WindowStyle Hidden" nocase ascii
        $nop    = "-NonInteractive" nocase ascii
    condition:
        any of ($enc1, $enc2, $enc3) or 2 of ($bypass, $hidden, $nop)
}
