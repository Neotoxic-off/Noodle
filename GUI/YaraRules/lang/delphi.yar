// severity: safe
rule Lang_Delphi {
    meta:
        description = "Borland / Embarcadero Delphi compiled binary"
    strings:
        $borland = "Borland" ascii
        $tform   = "TForm" ascii
        $tappl   = "TApplication" ascii
        $tobj    = "TObject" ascii
        $rtti    = "@Sysinit" ascii
        $rtl     = "System.pas" ascii
        $delphi  = "Embarcadero" ascii
    condition:
        3 of them
}

// severity: safe
rule Lang_FreePascal {
    meta:
        description = "Free Pascal / Lazarus compiled binary"
    strings:
        $fpcmain  = "FPC_INITIALIZEUNITS" ascii
        $fpcrt    = "FPC_RAISREEXCEPTION" ascii
        $fpcsys   = "FPC_SYSTEMINIT" ascii
        $lazarus  = "Lazarus" ascii
        $fpcsig   = "Free Pascal" ascii
        $fpcio    = "FPC_IOCHECK" ascii
    condition:
        any of them
}
