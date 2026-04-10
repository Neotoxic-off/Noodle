// severity: safe
rule Lang_NodeJS {
    meta:
        description = "Node.js binary — V8 / libuv / napi references"
    strings:
        $v8iso = "v8::Isolate" ascii
        $libuv = "libuv" ascii
        $uvrun = "uv_run" ascii
        $napi  = "napi_" ascii
    condition:
        // Require at least one V8/napi indicator paired with libuv
        // node_modules alone is too generic (appears in any bundled web app)
        ($v8iso or $napi) and ($libuv or $uvrun)
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
