// severity: safe
rule Lang_Go {
    meta:
        description = "Go binary — buildinfo section or Go runtime symbols"
    strings:
        $buildinfo = "go.buildinfo" ascii
        $goversion = "go1." ascii
        $gopanic   = "runtime.gopanic" ascii
        $gomain    = "main.main" ascii
        $gothread  = "GoExitThread" ascii
        $gosched   = "runtime.schedule" ascii
        $gostack   = "runtime.newstack" ascii
        $goroutine = "goroutine" ascii
    condition:
        2 of them
}
