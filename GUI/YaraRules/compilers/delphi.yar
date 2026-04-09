// severity: safe
rule Compiler_Delphi {
    meta:
        description = "Borland / Embarcadero Delphi compiled binary — CODE/DATA sections and Delphi RTTI"
    strings:
        $borland  = "Borland" ascii
        $tform    = "TForm" ascii
        $tappl    = "TApplication" ascii
        $tobj     = "TObject" ascii
        $rtti     = "@Sysinit" ascii
        $rtl      = "System.pas" ascii
        $delphi   = "Embarcadero" ascii
    condition:
        3 of them
}
