// severity: safe
rule Compiler_AutoIt {
    meta:
        description = "AutoIt v3 compiled script — runtime or compiled script markers present"
    strings:
        $dll    = "autoit3.dll" nocase
        $sec    = ">AUTOIT" ascii
        $str    = "AutoIt v3" ascii
        $wndcls = "AutoItWindowInfo" ascii
        $guard  = "This is a compiled AutoIt" ascii
    condition:
        any of them
}
