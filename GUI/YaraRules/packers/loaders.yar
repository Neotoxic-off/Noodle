// severity: dangerous
rule Packer_UPX {
    meta:
        description = "UPX packed binary — UPX0/UPX1 sections or decompression stub"
    strings:
        $name0    = "UPX0" ascii
        $name1    = "UPX1" ascii
        $magic    = "UPX!" ascii
        $stub_x86 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub_x64 = { 53 51 52 56 57 55 41 54 41 55 41 56 41 57 48 8D 35 }
    condition:
        ($name0 and $name1) or $magic or $stub_x86 or $stub_x64
}

// severity: dangerous
rule Packer_ASPack {
    meta:
        description = "ASPack — .aspack/.adata sections or decompression stub"
    strings:
        $sec1 = ".aspack" ascii
        $sec2 = ".adata" ascii
        $str  = "ASPack" ascii
        $stub = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? }
    condition:
        any of them
}

// severity: dangerous
rule Packer_MPRESS {
    meta:
        description = "MPRESS — .MPRESS1/.MPRESS2 sections"
    strings:
        $sec1  = ".MPRESS1" ascii
        $sec2  = ".MPRESS2" ascii
        $magic = { 60 E8 00 00 00 00 58 2D 05 00 00 00 }
    condition:
        ($sec1 and $sec2) or $magic
}

// severity: dangerous
rule Packer_NSPack {
    meta:
        description = "NSPack — .nsp0/.nsp1 sections"
    strings:
        $sec0 = ".nsp0" ascii
        $sec1 = ".nsp1" ascii
        $sec2 = ".nspack" ascii
    condition:
        ($sec0 and $sec1) or $sec2
}

// severity: dangerous
rule Packer_PECompact {
    meta:
        description = "PECompact — JCME signature or .pec section"
    strings:
        $sig = { 4A 43 4D 45 }
        $str = "PECompact" ascii
        $sec = ".pec" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_Petite {
    meta:
        description = "Petite packer — .petite section"
    strings:
        $section = ".petite" ascii
        $stub    = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 }
    condition:
        $section or $stub
}
