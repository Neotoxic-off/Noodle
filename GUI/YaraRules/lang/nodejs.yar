// severity: safe
rule Lang_NodeJS {
    meta:
        description = "Node.js binary — V8 / libuv / napi references"
    strings:
        $v8iso  = "v8::Isolate" ascii
        $libuv  = "libuv" ascii
        $uvrun  = "uv_run" ascii
        $napi   = "napi_" ascii
        $npm    = "node_modules" ascii
    condition:
        2 of them
}

// severity: safe
rule Lang_NodeJS_pkg {
    meta:
        description = "Node.js bundled with pkg (Vercel) or nexe"
    strings:
        $nexe     = "__nexe_" ascii
        $pkg      = "__pkg__" ascii
        $snapshot = "/snapshot/" ascii
    condition:
        any of them
}
