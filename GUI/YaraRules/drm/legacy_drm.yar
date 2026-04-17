// severity: safe
rule DRM_SecuROM {
    meta:
        description = "SecuROM DRM (Sony DADC) — legacy disc-based DRM"
    strings:
        $sr1 = "SecuROM" ascii nocase
        $sr2 = "SECUROM" ascii
        $sr3 = "SecuROM by Sony DADC" ascii nocase
        $sr4 = "AddD" ascii
    condition:
        any of them
}

// severity: safe
rule DRM_SafeDisc {
    meta:
        description = "SafeDisc DRM — legacy CD/DVD protection (Macrovision)"
    strings:
        $sd1 = "SafeDisc" ascii nocase
        $sd2 = "SAFEDISC" ascii
        $sd3 = "drvmgt.dll" ascii nocase
        $sd4 = "secdrv.sys" ascii nocase
        $sd5 = "clcd16.dll" ascii nocase
    condition:
        any of them
}

// severity: safe
rule DRM_StarForce {
    meta:
        description = "StarForce DRM (Protection Technology)"
    strings:
        $sf1 = "StarForce" ascii nocase
        $sf2 = "protect.dll" ascii nocase
        $sf3 = "sfloader.dll" ascii nocase
        $sf4 = "sfddrv.sys" ascii nocase
    condition:
        any of them
}

// severity: safe
rule DRM_TAGES {
    meta:
        description = "TAGES DRM (Ubisoft)"
    strings:
        $tg1 = "TAGES" ascii nocase
        $tg2 = "tagessetup.dll" ascii nocase
        $tg3 = "tagesclient.dll" ascii nocase
    condition:
        any of them
}
