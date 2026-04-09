// severity: dangerous
rule Packer_y0da {
    meta:
        description = "y0da Crypter — .y0da section"
    strings:
        $sec = ".y0da" ascii
    condition:
        $sec
}

// severity: dangerous
rule Packer_SVKP {
    meta:
        description = "SVKP packer — .svkp section"
    strings:
        $sec = ".svkp" ascii
    condition:
        $sec
}

// severity: dangerous
rule Packer_PEPACK {
    meta:
        description = "PEPACK — .PEPACK section"
    strings:
        $sec = ".PEPACK" ascii
    condition:
        $sec
}

// severity: dangerous
rule Packer_PEBundle {
    meta:
        description = "PEBundle — .pebundle section"
    strings:
        $sec = ".pebundle" ascii
    condition:
        $sec
}

// severity: suspicious
rule Packer_ByDzik {
    meta:
        description = "ByDzik packer — .ByDzik section"
    strings:
        $sec = ".ByDzik" ascii
    condition:
        $sec
}

// severity: suspicious
rule Packer_Perplex {
    meta:
        description = "Perplex protector — .perplex section"
    strings:
        $sec = ".perplex" ascii
    condition:
        $sec
}

// severity: suspicious
rule Packer_Boxed {
    meta:
        description = "Boxed packer — .boxed section"
    strings:
        $sec = ".boxed" ascii
    condition:
        $sec
}

// severity: suspicious
rule Packer_Shrink {
    meta:
        description = "Generic compressor — .shrink / .ccg / .neolit section"
    strings:
        $sec1 = ".shrink" ascii
        $sec2 = ".ccg" ascii
        $sec3 = ".neolit" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_Andromeda {
    meta:
        description = "Andromeda / Gamarue crypter — known section markers"
    strings:
        $sec = ".androm" ascii nocase
        $str = "Andromeda" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_CryptoObfuscator {
    meta:
        description = "Crypto Obfuscator for .NET — obfuscated .NET assembly"
    strings:
        $co1 = "CryptoObfuscator" ascii
        $co2 = "CO_Encrypted" ascii
    condition:
        any of them
}
