// severity: safe
rule DRM_EasyAntiCheat {
    meta:
        description = "Easy Anti-Cheat (EAC) anti-cheat system"
    strings:
        $eac1 = "EasyAntiCheat" ascii nocase
        $eac2 = "EasyAntiCheat.exe" ascii nocase
        $eac3 = "EasyAntiCheat_Setup.exe" ascii nocase
        $eac4 = "easyanticheat.net" ascii nocase
        $eac5 = "EAC_" ascii
        $eac6 = "EasyAntiCheat.sys" ascii nocase
    condition:
        any of them
}

// severity: safe
rule DRM_BattlEye {
    meta:
        description = "BattlEye anti-cheat system"
    strings:
        $be1 = "BattlEye" ascii nocase
        $be2 = "BEService.exe" ascii nocase
        $be3 = "BEClient.dll" ascii nocase
        $be4 = "battleye.com" ascii nocase
        $be5 = "BEDaisy" ascii nocase
        $be6 = "BattleEye" ascii nocase
    condition:
        any of them
}

// severity: safe
rule DRM_Vanguard {
    meta:
        description = "Riot Vanguard anti-cheat kernel driver"
    strings:
        $vg1 = "vgc.exe" ascii nocase
        $vg2 = "vgk.sys" ascii nocase
        $vg3 = "Vanguard" ascii nocase
        $vg4 = "RiotVanguard" ascii nocase
        $vg5 = "riot.com" ascii nocase
    condition:
        2 of them
}
