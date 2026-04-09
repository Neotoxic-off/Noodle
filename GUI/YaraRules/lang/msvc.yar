// severity: safe
rule Lang_MSVC_Modern {
    meta:
        description = "Compiled with Microsoft Visual C++ 2015+ (vcruntime140)"
    strings:
        $vcr140  = "vcruntime140.dll" nocase ascii
        $vcr1401 = "vcruntime140_1.dll" nocase ascii
        $msvcp   = "msvcp140.dll" nocase ascii
        $msvcr   = "msvcr140.dll" nocase ascii
    condition:
        any of them
}

// severity: safe
rule Lang_MSVC_Legacy {
    meta:
        description = "Compiled with Visual C++ 2013 or earlier"
    strings:
        $r120 = "msvcr120.dll" nocase ascii
        $r110 = "msvcr110.dll" nocase ascii
        $r100 = "msvcr100.dll" nocase ascii
        $r90  = "msvcr90.dll" nocase ascii
        $r80  = "msvcr80.dll" nocase ascii
        $r71  = "msvcr71.dll" nocase ascii
    condition:
        any of them
}

// severity: safe
rule Lang_MinGW {
    meta:
        description = "Compiled with GCC / MinGW — GNU runtime imports"
    strings:
        $mingw1 = "__mingw_" ascii
        $libgcc = "libgcc_" ascii nocase
        $libstd = "libstdc++" ascii nocase
        $mingwex = "mingwex" ascii nocase
    condition:
        any of them
}

// severity: safe
rule Lang_Clang {
    meta:
        description = "Compiled with Clang/LLVM — LLVM runtime or exception table markers"
    strings:
        $llvm1 = "LLVM" ascii
        $clang = "clang" ascii nocase
        $llvmeh = "__llvm_prf_" ascii
        $llvmcov = "__llvm_covmap" ascii
    condition:
        2 of them
}
