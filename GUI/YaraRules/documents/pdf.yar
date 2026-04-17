// severity: suspicious
rule Document_PDF_Suspicious {
    meta:
        description = "PDF with embedded JavaScript or launch action"
    strings:
        $pdf_magic = { 25 50 44 46 }
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $launch = "/Launch" ascii
        $openaction = "/OpenAction" ascii
        $aa = "/AA" ascii fullword
        $uri = "/URI" ascii
        $embed = "/EmbeddedFile" ascii
        $xfa  = "/XFA" ascii
    condition:
        $pdf_magic and ($js1 or $js2 or $launch or $openaction or $aa)
}

// severity: dangerous
rule Document_PDF_Exploit {
    meta:
        description = "PDF with exploit-related strings (shellcode, spray)"
    strings:
        $pdf_magic = { 25 50 44 46 }
        $unescape  = "unescape" ascii nocase
        $shellcode = "shellcode" ascii nocase
        $spray     = "heap" ascii nocase
        $cmd       = "cmd.exe" ascii nocase
        $ps        = "powershell" ascii nocase
        $nop_sled  = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $pdf_magic and 2 of ($unescape, $shellcode, $spray, $cmd, $ps, $nop_sled)
}
