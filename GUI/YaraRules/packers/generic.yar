// severity: dangerous
rule Packer_VMProtect {
    meta:
        description = "VMProtect protected binary — code virtualization sections .vmp0/.vmp1"
    strings:
        $vmp0   = ".vmp0" ascii
        $vmp1   = ".vmp1" ascii
        $vmpstr = "VMProtect" ascii
    condition:
        ($vmp0 and $vmp1) or $vmpstr
}

// severity: dangerous
rule Packer_Enigma {
    meta:
        description = "Enigma Protector — .enigma1/.enigma2 sections or protector string"
    strings:
        $sec1 = ".enigma1" ascii
        $sec2 = ".enigma2" ascii
        $str  = "Enigma Protector" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_Petite {
    meta:
        description = "Petite packer — .petite section or unpacking stub"
    strings:
        $section = ".petite" ascii
        $stub    = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 }
    condition:
        $section or $stub
}

// severity: dangerous
rule Packer_Y0Da {
    meta:
        description = "y0da Crypter — .y0da section name"
    strings:
        $section = ".y0da" ascii
    condition:
        $section
}

// severity: dangerous
rule Packer_SVKP {
    meta:
        description = "SVKP packer — .svkp section name"
    strings:
        $section = ".svkp" ascii
    condition:
        $section
}

// severity: dangerous
rule Packer_PEPACK {
    meta:
        description = "PEPACK packer — .PEPACK section name"
    strings:
        $section = ".PEPACK" ascii
    condition:
        $section
}

// severity: dangerous
rule Packer_PEBundle {
    meta:
        description = "PEBundle packer — .pebundle section name"
    strings:
        $section = ".pebundle" ascii
    condition:
        $section
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

// severity: suspicious
rule Packer_ByDzik {
    meta:
        description = "ByDzik packer — .ByDzik section name"
    strings:
        $section = ".ByDzik" ascii
    condition:
        $section
}

// severity: suspicious
rule Packer_Perplex {
    meta:
        description = "Perplex protector — .perplex section name"
    strings:
        $section = ".perplex" ascii
    condition:
        $section
}

// severity: suspicious
rule Packer_Boxed {
    meta:
        description = "Boxed packer — .boxed section name"
    strings:
        $section = ".boxed" ascii
    condition:
        $section
}

// severity: suspicious
rule Packer_Generic_Shrink {
    meta:
        description = "Unknown compressor — .shrink or .ccg section name"
    strings:
        $shrink = ".shrink" ascii
        $ccg    = ".ccg" ascii
        $neolit = ".neolit" ascii
    condition:
        any of them
}
