// severity: safe
rule Lang_Go {
    meta:
        description = "Go binary — buildinfo section or Go runtime symbols"
    strings:
        // Stable Go runtime symbols (unchanged across all Go versions)
        $buildinfo = "go.buildinfo" ascii
        $gopanic   = "runtime.gopanic" ascii
        $gosched   = "runtime.schedule" ascii
        $gostack   = "runtime.newstack" ascii
        $gothread  = "GoExitThread" ascii
        $goitab    = "runtime.itab" ascii
        $gomalloc  = "runtime.mallocgc" ascii
        $goexit    = "runtime.goexit" ascii
    condition:
        $buildinfo or $gopanic or 2 of ($gosched, $gostack, $gothread, $goitab, $gomalloc, $goexit)
}
