// severity: safe
rule Compiler_Python_PyInstaller {
    meta:
        description = "Python frozen with PyInstaller — contains MEI bootstrap markers"
    strings:
        $mei      = "_MEIPASS2" ascii
        $manifest = "pyi-windows-manifest-filename" ascii
        $hook     = "pyi_rth_" ascii
        $loader   = "PKG-00.pkg" ascii
    condition:
        any of them
}

// severity: safe
rule Compiler_Python_Runtime {
    meta:
        description = "Python script compiled to executable — Python runtime DLL imported"
    strings:
        $py38  = "python38.dll" nocase
        $py39  = "python39.dll" nocase
        $py310 = "python310.dll" nocase
        $py311 = "python311.dll" nocase
        $py312 = "python312.dll" nocase
        $py313 = "python313.dll" nocase
    condition:
        any of them
}
