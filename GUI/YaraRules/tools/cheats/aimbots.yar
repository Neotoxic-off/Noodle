// severity: suspicious
rule Tool_Aimbot_Generic {
    meta:
        description = "Generic aimbot / wallhack / ESP cheat strings"
    strings:
        $ab1 = "aimbot" ascii nocase
        $ab2 = "aim_bot" ascii nocase
        $ab3 = "wallhack" ascii nocase
        $ab4 = "wall_hack" ascii nocase
        $ab5 = "triggerbot" ascii nocase
        $ab6 = "trigger_bot" ascii nocase
        $ab7 = "ESP" ascii fullword
        $ab8 = "no recoil" ascii nocase
        $ab9 = "no spread" ascii nocase
        $ab10 = "bhop" ascii nocase fullword
        $ab11 = "bunnyhop" ascii nocase
        $glow = "glow_enabled" ascii nocase
        $bone = "bone_matrix" ascii nocase
        $rcs  = "RecoilControl" ascii nocase
    condition:
        3 of them
}

// severity: suspicious
rule Tool_ExternalCheat {
    meta:
        description = "External game cheat — process memory read/write pattern"
    strings:
        $r1 = "ReadProcessMemory" ascii
        $w1 = "WriteProcessMemory" ascii
        $op = "OpenProcess" ascii
        $pid = "GetWindowThreadProcessId" ascii
        $mod = "GetModuleBaseAddress" ascii nocase
        $vp  = "VirtualProtectEx" ascii
        $game1 = "cs2.exe" ascii nocase
        $game2 = "RustClient.exe" ascii nocase
        $game3 = "EscapeFromTarkov.exe" ascii nocase
        $game4 = "ac_client.exe" ascii nocase
        $game5 = "GTA5.exe" ascii nocase
    condition:
        $r1 and $op and 1 of ($game1, $game2, $game3, $game4, $game5)
}
