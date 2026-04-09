// severity: safe
rule Lang_DotNet {
    meta:
        description = ".NET CLR binary — BSJB metadata signature or mscoree import"
    strings:
        $mscoree = "mscoree.dll" nocase ascii
        $bsjb    = { 42 53 4A 42 }
        $cor_exe = "_CorExeMain" ascii
        $cor_dll = "_CorDllMain" ascii
        $mscorlib = "mscorlib" ascii
    condition:
        $mscoree or $bsjb or $cor_exe or $cor_dll
}

// severity: safe
rule Lang_DotNet_Obfuscated {
    meta:
        description = ".NET binary with obfuscator traces (ConfuserEx, Dotfuscator, SmartAssembly)"
    strings:
        $confuser  = "ConfuserEx" ascii
        $dotfusc   = "Dotfuscator" ascii
        $smart     = "SmartAssembly" ascii
        $reactor   = ".NET Reactor" ascii
        $eazfusc   = "Eazfuscator" ascii
        $babel     = "Babel" ascii
        $de4dot    = "de4dot" ascii
    condition:
        any of them
}
