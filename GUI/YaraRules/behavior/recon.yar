// severity: suspicious
rule Behavior_Recon_SystemInfo {
    meta:
        description = "System enumeration — OS version, hardware, or user account discovery"
    strings:
        $getcomp = "GetComputerNameA" fullword ascii
        $getusr  = "GetUserNameA" fullword ascii
        $netbios = "GetComputerNameExA" fullword ascii
        $sysinfo = "GetSystemInfo" fullword ascii
        $osver   = "GetVersionExA" fullword ascii
        $netapi  = "NetUserEnum" fullword ascii
        $netgrp  = "NetGroupEnum" fullword ascii
    condition:
        3 of them
}

// severity: suspicious
rule Behavior_Recon_ProcessEnum {
    meta:
        description = "Process enumeration — enumerates running processes"
    strings:
        $snap  = "CreateToolhelp32Snapshot" fullword ascii
        $first = "Process32First" fullword ascii
        $next  = "Process32Next" fullword ascii
        $psmA  = "EnumProcesses" fullword ascii
        $wts   = "WTSEnumerateProcesses" fullword ascii
    condition:
        ($snap and ($first or $next)) or $psmA or $wts
}

// severity: suspicious
rule Behavior_Recon_NetworkScan {
    meta:
        description = "Network adapter or ARP table enumeration — network reconnaissance"
    strings:
        $arp   = "GetIpNetTable" fullword ascii
        $route = "GetIpForwardTable" fullword ascii
        $adap  = "GetAdaptersInfo" fullword ascii
        $adap2 = "GetAdaptersAddresses" fullword ascii
        $iflist = "if_nameindex" ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Recon_DiskEnum {
    meta:
        description = "Disk and volume enumeration — maps drives before data theft"
    strings:
        $logdrvA = "GetLogicalDriveStringsA" fullword ascii
        $logdrvW = "GetLogicalDriveStringsW" fullword ascii
        $drvtype = "GetDriveTypeA" fullword ascii
        $diskfree = "GetDiskFreeSpaceEx" fullword ascii
    condition:
        2 of them
}
