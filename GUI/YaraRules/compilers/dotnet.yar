// severity: safe
rule Compiler_DotNet {
    meta:
        description = ".NET CLR binary — imports mscoree.dll or contains BSJB metadata signature"
    strings:
        $mscoree  = "mscoree.dll" nocase
        $bsjb     = { 42 53 4A 42 }
        $cor_exe  = "_CorExeMain" ascii
        $cor_dll  = "_CorDllMain" ascii
        $mscorlib = "mscorlib" ascii
    condition:
        $mscoree or $bsjb or $cor_exe or $cor_dll
}
