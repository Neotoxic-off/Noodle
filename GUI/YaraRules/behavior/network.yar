// severity: suspicious
rule Behavior_Network_WinHTTP {
    meta:
        description = "WinHTTP — binary communicates over HTTP/HTTPS"
    strings:
        $open    = "WinHttpOpen" fullword ascii
        $connect = "WinHttpConnect" fullword ascii
        $send    = "WinHttpSendRequest" fullword ascii
        $recv    = "WinHttpReceiveResponse" fullword ascii
    condition:
        $open and ($connect or $send)
}

// severity: suspicious
rule Behavior_Network_WinInet {
    meta:
        description = "WinINet — binary accesses internet resources"
    strings:
        $openA = "InternetOpenA" fullword ascii
        $openW = "InternetOpenW" fullword ascii
        $urlA  = "InternetOpenUrlA" fullword ascii
        $urlW  = "InternetOpenUrlW" fullword ascii
        $httpA = "HttpSendRequestA" fullword ascii
        $httpW = "HttpSendRequestW" fullword ascii
    condition:
        any of them
}

// severity: dangerous
rule Behavior_Network_DownloadExec {
    meta:
        description = "URLDownloadToFile — downloads payloads from internet (dropper)"
    strings:
        $dlA = "URLDownloadToFileA" fullword ascii
        $dlW = "URLDownloadToFileW" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Network_RawSocket {
    meta:
        description = "Winsock primitives — low-level custom network communication"
    strings:
        $wsa    = "WSAStartup" fullword ascii
        $socket = "socket" fullword ascii
        $bind   = "bind" fullword ascii
        $send   = "send" fullword ascii
        $recv   = "recv" fullword ascii
        $wsaconn = "WSAConnect" fullword ascii
    condition:
        $wsa and 2 of ($socket, $bind, $send, $recv, $wsaconn)
}

// severity: suspicious
rule Behavior_Network_FTP {
    meta:
        description = "FTP transfer functions — binary may exfiltrate via FTP"
    strings:
        $putA = "FtpPutFileA" fullword ascii
        $putW = "FtpPutFileW" fullword ascii
        $getA = "FtpGetFileA" fullword ascii
        $getW = "FtpGetFileW" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Network_DNS {
    meta:
        description = "Direct DNS resolution functions — may use DNS for C2 or tunneling"
    strings:
        $dns1 = "DnsQuery_A" fullword ascii
        $dns2 = "DnsQuery_W" fullword ascii
        $dns3 = "DnsQueryEx" fullword ascii
    condition:
        any of them
}
