// severity: safe
rule Compiler_Go {
    meta:
        description = "Go binary — .go.buildinfo section or Go runtime symbols present"
    strings:
        $buildinfo = "go.buildinfo" ascii
        $goversion = "go1." ascii
        $gopanic   = "runtime.gopanic" ascii
        $gomain    = "main.main" ascii
        $gothread  = "GoExitThread" ascii
        $gosched   = "runtime.schedule" ascii
        $gostack   = "runtime.newstack" ascii
    condition:
        2 of them
}
