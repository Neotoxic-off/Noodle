// severity: dangerous
rule Packer_MPRESS {
    meta:
        description = "MPRESS compressed binary — .MPRESS1/.MPRESS2 sections or stub detected"
    strings:
        $sec1  = ".MPRESS1" ascii
        $sec2  = ".MPRESS2" ascii
        $magic = { 60 E8 00 00 00 00 58 2D 05 00 00 00 }
    condition:
        ($sec1 and $sec2) or $magic
}
