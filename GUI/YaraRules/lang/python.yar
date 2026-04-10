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
        description = "Python script compiled to executable — Python C API or runtime DLL present"
    strings:
        // Stable C API functions (unchanged across Python 2–4+)
        $init    = "Py_Initialize" ascii
        $eval    = "PyEval_EvalCode" ascii
        $import  = "PyImport_ImportModule" ascii
        $run     = "PyRun_SimpleString" ascii
        // Generic DLL prefix — matches python38.dll, python312.dll, python315.dll, etc.
        $py3dll  = "python3" nocase ascii
        $py2dll  = "python27.dll" nocase ascii
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
