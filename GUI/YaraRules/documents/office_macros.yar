// severity: suspicious
rule Document_OfficeMacro_VBA {
    meta:
        description = "Office document with VBA macro indicators"
    strings:
        $vba1 = "AutoOpen" ascii nocase
        $vba2 = "AutoClose" ascii nocase
        $vba3 = "Document_Open" ascii nocase
        $vba4 = "Workbook_Open" ascii nocase
        $vba5 = "Shell" ascii fullword
        $vba6 = "WScript.Shell" ascii nocase
        $vba7 = "CreateObject" ascii nocase
        $vba8 = "Chr(" ascii nocase
        $vba9 = "Execute" ascii nocase fullword
        $vba10 = "VBA" ascii fullword
        $ps   = "PowerShell" ascii nocase
        $cmd  = "cmd.exe" ascii nocase
    condition:
        ($vba1 or $vba2 or $vba3 or $vba4) and 3 of ($vba5, $vba6, $vba7, $vba8, $vba9, $ps, $cmd)
}

// severity: dangerous
rule Document_Macro_Dropper {
    meta:
        description = "Macro dropper — shell execution + download pattern"
    strings:
        $d1 = "URLDownloadToFile" ascii nocase
        $d2 = "DownloadFile" ascii nocase
        $d3 = "bitsadmin" ascii nocase
        $d4 = "certutil" ascii nocase
        $d5 = "mshta" ascii nocase
        $d6 = "wscript.exe" ascii nocase
        $d7 = "cscript.exe" ascii nocase
        $open = "AutoOpen" ascii nocase
        $wkb  = "Workbook_Open" ascii nocase
        $shell = "Shell" ascii fullword
    condition:
        ($open or $wkb) and $shell and any of ($d1, $d2, $d3, $d4, $d5, $d6, $d7)
}

// severity: suspicious
rule Document_OLE_Compound {
    meta:
        description = "OLE2 compound document (Word/Excel/PowerPoint legacy format)"
    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $word = "Word.Document" ascii nocase
        $excel = "Excel.Sheet" ascii nocase
        $ppt   = "PowerPoint" ascii nocase
    condition:
        $ole_magic and any of ($word, $excel, $ppt)
}

// severity: dangerous
rule Document_DDEAUTO {
    meta:
        description = "DDE/DDEAUTO code execution via Office documents"
    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE" ascii fullword
        $dde3 = "cmd.exe" ascii nocase
        $dde4 = "mshta.exe" ascii nocase
        $dde5 = "wscript.exe" ascii nocase
    condition:
        $dde1 or ($dde2 and any of ($dde3, $dde4, $dde5))
}
