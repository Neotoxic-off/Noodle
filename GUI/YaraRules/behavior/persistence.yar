// severity: suspicious
rule Behavior_Persistence_Service {
    meta:
        description = "Service Control Manager — binary may install a Windows service"
    strings:
        $openA   = "OpenSCManagerA" fullword ascii
        $openW   = "OpenSCManagerW" fullword ascii
        $createA = "CreateServiceA" fullword ascii
        $createW = "CreateServiceW" fullword ascii
        $startA  = "StartServiceA" fullword ascii
        $startW  = "StartServiceW" fullword ascii
    condition:
        ($openA or $openW) and ($createA or $createW or $startA or $startW)
}

// severity: suspicious
rule Behavior_Persistence_Registry {
    meta:
        description = "Registry Run key write — classic autorun persistence"
    strings:
        $setA = "RegSetValueExA" fullword ascii
        $setW = "RegSetValueExW" fullword ascii
        $runA = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $runB = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $runS = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
    condition:
        // Must have a write API call; the path alone is not enough (appears in scanners/docs)
        ($setA or $setW) and ($runA or $runB or $runS)
}

// severity: suspicious
rule Behavior_Persistence_ScheduledTask {
    meta:
        description = "Scheduled task creation — persistence via Task Scheduler"
    strings:
        $schtask = "schtasks" ascii nocase
        $sch1    = "ITaskScheduler" ascii
        $sch2    = "ITaskService" ascii
        $sch3    = "RegisterTask" ascii
        $atjobs  = "SYSTEM32\\Tasks" ascii nocase
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Persistence_Startup {
    meta:
        description = "Startup folder write — copy to startup directory for persistence"
    strings:
        $start1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii nocase
        $start2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu" ascii nocase
        $start3 = "CurrentVersion\\Explorer\\Shell Folders" ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Persistence_Bootkit {
    meta:
        description = "Boot sector / bootkit techniques — raw disk access"
    strings:
        $mbr1 = "\\\\.\\PhysicalDrive0" ascii nocase
        $mbr2 = "\\\\.\\HarddiskVolume" ascii nocase
        $raw1 = "DeviceIoControl" fullword ascii
        $raw2 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii
    condition:
        ($mbr1 or $mbr2) and $raw1
}
