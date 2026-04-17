// severity: suspicious
rule Tool_GameTrainer {
    meta:
        description = "Game trainer / cheat tool — memory patcher for games"
    strings:
        $tr1 = "trainer" ascii nocase fullword
        $tr2 = "cheat engine" ascii nocase
        $tr3 = "CheatEngine" ascii nocase
        $tr4 = "infinite health" ascii nocase
        $tr5 = "infinite ammo" ascii nocase
        $tr6 = "god mode" ascii nocase
        $tr7 = "no clip" ascii nocase
        $tr8 = "unlimited lives" ascii nocase
        $tr9 = "WriteProcessMemory" ascii
        $mem = "VirtualProtectEx" ascii
        $proc = "OpenProcess" ascii
    condition:
        ($tr9 and $mem and $proc and 2 of ($tr4, $tr5, $tr6, $tr7, $tr8))
        or 2 of ($tr1, $tr2, $tr3)
}

// severity: suspicious
rule Tool_CheatEngine {
    meta:
        description = "Cheat Engine memory scanner / game hacking tool"
    strings:
        $ce1 = "Cheat Engine" ascii nocase
        $ce2 = "CheatEngine" ascii nocase
        $ce3 = "cheatengine.org" ascii nocase
        $ce4 = "dbk32.dll" ascii nocase
        $ce5 = "dbk64.dll" ascii nocase
        $ce6 = "cedriver.sys" ascii nocase
        $ce7 = "speedhack" ascii nocase
    condition:
        any of them
}
