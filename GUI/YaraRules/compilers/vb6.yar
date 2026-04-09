// severity: safe
rule Compiler_VisualBasic6 {
    meta:
        description = "Visual Basic 6.0 compiled binary — imports VB6 runtime DLL"
    strings:
        $vbvm60 = "msvbvm60.dll" nocase
        $vbvm50 = "msvbvm50.dll" nocase
    condition:
        any of them
}
