// severity: safe
rule Framework_NSIS {
    meta:
        description = "NSIS (Nullsoft Scriptable Install System) installer"
    strings:
        $nsis1 = "Nullsoft Install System" ascii
        $nsis2 = "NSIS Error" ascii
        $nsis3 = { 4E 53 49 53 }
    condition:
        any of them
}

// severity: safe
rule Framework_InnoSetup {
    meta:
        description = "Inno Setup installer"
    strings:
        $inno1 = "Inno Setup" ascii
        $inno2 = "This installation was built with Inno Setup" ascii
        $inno3 = "JRSoftware" ascii
    condition:
        any of them
}

// severity: safe
rule Framework_WiX {
    meta:
        description = "WiX Toolset MSI installer"
    strings:
        $wix1 = "WiX Toolset" ascii
        $wix2 = "WixUI" ascii
        $wix3 = "WixSharp" ascii
    condition:
        any of them
}

// severity: safe
rule Framework_InstallShield {
    meta:
        description = "InstallShield installer"
    strings:
        $is1 = "InstallShield" ascii
        $is2 = "Flexera" ascii
        $is3 = "iKernel.dll" ascii nocase
    condition:
        any of them
}

// severity: safe
rule Framework_AdvancedInstaller {
    meta:
        description = "Advanced Installer package"
    strings:
        $ai1 = "Advanced Installer" ascii
        $ai2 = "Caphyon" ascii
    condition:
        any of them
}
