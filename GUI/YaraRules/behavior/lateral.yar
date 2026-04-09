// severity: suspicious
rule Behavior_Lateral_WMI {
    meta:
        description = "WMI (Windows Management Instrumentation) usage — remote execution or recon"
    strings:
        $wmi1  = "WbemLocator" ascii
        $wmi2  = "IWbemServices" ascii
        $wmi3  = "ConnectServer" ascii
        $wmi4  = "ExecQuery" ascii
        $wmic  = "wmic.exe" ascii nocase
        $wmiexec = "Win32_Process" ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Lateral_SMB {
    meta:
        description = "SMB / file share access — lateral movement or credential relay"
    strings:
        $smb1  = "\\\\%s\\IPC$" ascii
        $smb2  = "\\\\%s\\ADMIN$" ascii
        $smb3  = "\\\\%s\\C$" ascii
        $netbios = "NetBIOS" ascii
        $netuse = "NetUseAdd" ascii
        $wnet  = "WNetAddConnection" ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Lateral_DCOM {
    meta:
        description = "DCOM / COM activation — remote code execution via COM"
    strings:
        $dcom1 = "CoCreateInstanceEx" fullword ascii
        $dcom2 = "IRemoteActivation" ascii
        $dcom3 = "CLSCTX_REMOTE_SERVER" ascii
        $dcom4 = "CoGetObject" fullword ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Lateral_WinRM {
    meta:
        description = "WinRM / WSMan — remote PowerShell execution"
    strings:
        $wsm1 = "WSManCreateSession" ascii
        $wsm2 = "WSManRunShellCommand" ascii
        $psrp = "Microsoft.PowerShell" ascii
    condition:
        any of ($wsm1, $wsm2)
}

// severity: suspicious
rule Behavior_Lateral_PassTheHash {
    meta:
        description = "NTLM hash references — possible pass-the-hash attack"
    strings:
        $ntlm1 = "NTLM" fullword ascii
        $pth1  = "NtlmCheckPassword" ascii
        $pth2  = "sekurlsa::pth" ascii
        $pth3  = "pass-the-hash" ascii nocase
    condition:
        2 of them
}
