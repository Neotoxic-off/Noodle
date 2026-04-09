// severity: suspicious
rule Behavior_Exfil_Clipboard {
    meta:
        description = "Reads clipboard contents — may steal copied data"
    strings:
        $open = "OpenClipboard" fullword ascii
        $get  = "GetClipboardData" fullword ascii
        $seq  = "CloseClipboard" fullword ascii
    condition:
        $open and $get
}

// severity: suspicious
rule Behavior_Exfil_BrowserCreds {
    meta:
        description = "Accesses browser credential or cookie storage paths"
    strings:
        $chrome   = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase
        $edge     = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii nocase
        $firefox  = "\\Mozilla\\Firefox\\Profiles" ascii nocase
        $opera    = "\\Opera Software\\Opera Stable\\Login Data" ascii nocase
        $brave    = "\\BraveSoftware\\Brave-Browser\\User Data\\Default" ascii nocase
        $cookies  = "\\Cookies" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Exfil_Credentials_LSASS {
    meta:
        description = "Access to LSASS process — credential dumping"
    strings:
        $lsass1 = "lsass.exe" ascii nocase
        $lsass2 = "lsass" ascii
        $seq    = "SeDebugPrivilege" ascii
        $mim    = "mimikatz" ascii nocase
    condition:
        ($lsass1 or $lsass2) and $seq
        or $mim
}

// severity: suspicious
rule Behavior_Exfil_FileSearch {
    meta:
        description = "Searches for sensitive file types — password managers, certificates, wallets"
    strings:
        $kdbx  = ".kdbx" ascii
        $kdb   = ".kdb" ascii
        $p12   = ".p12" ascii
        $pfx   = ".pfx" ascii
        $wallet = "wallet.dat" ascii nocase
        $pem   = ".pem" ascii
        $ppk   = ".ppk" ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Exfil_Screenshot_Combo {
    meta:
        description = "Screen capture + network combo — screenshot exfiltration pattern"
    strings:
        $bitblt  = "BitBlt" fullword ascii
        $getdc   = "GetDC" fullword ascii
        $winhttp = "WinHttpSendRequest" fullword ascii
        $wininet = "HttpSendRequestA" fullword ascii
    condition:
        ($bitblt and $getdc) and ($winhttp or $wininet)
}
