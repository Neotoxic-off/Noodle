// severity: safe
rule Lang_Python_PyInstaller {
    meta:
        description = "Python frozen with PyInstaller"
    strings:
        $mei      = "_MEIPASS2" ascii
        $manifest = "pyi-windows-manifest-filename" ascii
        $hook     = "pyi_rth_" ascii
        $loader   = "PKG-00.pkg" ascii
        $mei2     = "MEI_EXTRACT" ascii
    condition:
        any of them
}

// severity: safe
rule Lang_Python_Runtime {
    meta:
        description = "Python script compiled to executable — Python DLL imported"
    strings:
        $py38  = "python38.dll" nocase ascii
        $py39  = "python39.dll" nocase ascii
        $py310 = "python310.dll" nocase ascii
        $py311 = "python311.dll" nocase ascii
        $py312 = "python312.dll" nocase ascii
        $py313 = "python313.dll" nocase ascii
        $py314 = "python314.dll" nocase ascii
    condition:
        any of them
}

// severity: safe
rule Lang_Python_cx_Freeze {
    meta:
        description = "Python frozen with cx_Freeze"
    strings:
        $cxfreeze = "cx_Freeze" ascii
        $cxbase   = "cx_freeze_base" ascii
    condition:
        any of them
}

// severity: safe
rule Lang_Python_Nuitka {
    meta:
        description = "Python compiled with Nuitka"
    strings:
        $nuitka1 = "__nuitka_version__" ascii
        $nuitka2 = "nuitka_module_" ascii
        $nuitka3 = "NUITKA_ONEFILE_PARENT" ascii
    condition:
        any of them
}
