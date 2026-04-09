// severity: safe
rule Compiler_MSVC_2015plus {
    meta:
        description = "Compiled with Microsoft Visual C++ 2015 or later (vcruntime140)"
    strings:
        $vcrA = "vcruntime140.dll" nocase
        $vcrB = "vcruntime140_1.dll" nocase
        $msvA = "msvcp140.dll" nocase
        $msrA = "msvcr140.dll" nocase
    condition:
        any of them
}

// severity: safe
rule Compiler_MSVC_Legacy {
    meta:
        description = "Compiled with legacy MSVC runtime (Visual C++ 2013 and earlier)"
    strings:
        $r120 = "msvcr120.dll" nocase
        $r110 = "msvcr110.dll" nocase
        $r100 = "msvcr100.dll" nocase
        $r90  = "msvcr90.dll" nocase
        $r80  = "msvcr80.dll" nocase
    condition:
        any of them
}

// severity: safe
rule Compiler_MinGW {
    meta:
        description = "Compiled with GCC / MinGW — GNU runtime imports detected"
    strings:
        $mingw1 = "__mingw_" ascii
        $mingw2 = "___mingw_" ascii
        $libgcc = "libgcc_" nocase ascii
        $libstd = "libstdc++" nocase ascii
    condition:
        any of them
}
