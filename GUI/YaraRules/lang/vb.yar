// severity: safe
rule Lang_VisualBasic6 {
    meta:
        description = "Visual Basic 6.0 compiled binary — VB6 runtime DLL"
    strings:
        $vbvm60 = "msvbvm60.dll" nocase ascii
        $vbvm50 = "msvbvm50.dll" nocase ascii
    condition:
        any of them
}

// severity: safe
rule Lang_VisualBasicNET {
    meta:
        description = "Visual Basic .NET binary — VB runtime assembly reference"
    strings:
        $vbrt  = "Microsoft.VisualBasic" ascii
        $vbrt2 = "Microsoft.VisualBasic.Runtime" ascii
    condition:
        any of them
}
