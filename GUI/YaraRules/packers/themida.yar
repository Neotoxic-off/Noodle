// severity: dangerous
rule Packer_Themida {
    meta:
        description = "Themida / WinLicense protected binary — virtualization-based software protection"
    strings:
        $sec_themida = ".themida" ascii
        $sec_winlice = ".winlice" ascii
        $str_themida = "Themida" ascii
        $str_winlic  = "WinLicense" ascii
    condition:
        any of them
}
