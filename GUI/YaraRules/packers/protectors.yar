// severity: dangerous
rule Packer_VMProtect {
    meta:
        description = "VMProtect — .vmp0/.vmp1 sections or virtualization string"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $str  = "VMProtect" ascii
    condition:
        ($vmp0 and $vmp1) or $str
}

// severity: dangerous
rule Packer_Themida {
    meta:
        description = "Themida / WinLicense — virtualization-based software protection"
    strings:
        $sec1 = ".themida" ascii
        $sec2 = ".winlice" ascii
        $str1 = "Themida" ascii
        $str2 = "WinLicense" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_Enigma {
    meta:
        description = "Enigma Protector — .enigma1/.enigma2 sections"
    strings:
        $sec1 = ".enigma1" ascii
        $sec2 = ".enigma2" ascii
        $str  = "Enigma Protector" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_Obsidium {
    meta:
        description = "Obsidium software protection"
    strings:
        $sec = ".obsidium" ascii
        $str = "Obsidium" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_ExeCryptor {
    meta:
        description = "ExeCryptor software protection"
    strings:
        $sec = ".ex_cod" ascii
        $str = "ExeCryptor" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_CodeVirtualizer {
    meta:
        description = "Code Virtualizer (Oreans) — CV virtualization sections"
    strings:
        $sec1 = ".cv_data" ascii
        $sec2 = ".cv_code" ascii
        $str  = "Code Virtualizer" ascii
    condition:
        any of them
}

// severity: dangerous
rule Packer_StarForce {
    meta:
        description = "StarForce copy protection"
    strings:
        $sec = ".sforce" ascii
        $str = "StarForce" ascii
        $drv = "sfdrv" ascii nocase
    condition:
        any of them
}
