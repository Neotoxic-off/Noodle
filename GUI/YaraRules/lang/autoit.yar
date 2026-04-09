// severity: safe
rule Lang_AutoIt {
    meta:
        description = "AutoIt v3 compiled script"
    strings:
        $dll  = "autoit3.dll" nocase ascii
        $sec  = ">AUTOIT" ascii
        $str  = "AutoIt v3" ascii
        $cls  = "AutoItWindowInfo" ascii
        $guard = "This is a compiled AutoIt" ascii
    condition:
        any of them
}
