// severity: dangerous
rule Packer_NSPack {
    meta:
        description = "NSPack compressed binary — .nsp section names detected"
    strings:
        $sec0 = ".nsp0" ascii
        $sec1 = ".nsp1" ascii
        $sec2 = ".nspack" ascii
    condition:
        ($sec0 and $sec1) or $sec2
}
