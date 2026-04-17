// severity: safe
rule Engine_ValveSource {
    meta:
        description = "Valve Source Engine game binary"
    strings:
        $src1 = "Source Engine" ascii nocase
        $src2 = "Valve Corporation" ascii nocase
        $src3 = "GameInfo.txt" ascii nocase
        $src4 = "engine.dll" ascii nocase
        $src5 = "vstdlib.dll" ascii nocase
        $src6 = "tier0.dll" ascii nocase
        $src7 = "vphysics.dll" ascii nocase
        $src8 = "soundemittersystem.dll" ascii nocase
        $bsp  = ".bsp" ascii fullword
        $vpk  = ".vpk" ascii fullword
        $vmf  = ".vmf" ascii fullword
    condition:
        3 of ($src1, $src2, $src3, $src4, $src5, $src6, $src7, $src8)
        or (2 of ($bsp, $vpk, $vmf) and 1 of ($src3, $src4))
}
