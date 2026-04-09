// severity: safe
rule Framework_CEF {
    meta:
        description = "Chromium Embedded Framework (CEF)"
    strings:
        $cef1 = "libcef.dll" ascii nocase
        $cef2 = "cef_initialize" ascii
        $cef3 = "CefInitialize" ascii
        $cef4 = "cef_browser" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_WebView2 {
    meta:
        description = "Microsoft WebView2 (Edge-based embedding)"
    strings:
        $wv1 = "WebView2Loader.dll" ascii nocase
        $wv2 = "ICoreWebView2" ascii
        $wv3 = "CreateCoreWebView2Environment" ascii
    condition:
        any of them
}

// severity: safe
rule Framework_NWjs {
    meta:
        description = "NW.js (node-webkit) application"
    strings:
        $nw1 = "nwjs" ascii nocase
        $nw2 = "node-webkit" ascii nocase
        $nw3 = "nw.pak" ascii
        $nw4 = "package.json" ascii
    condition:
        2 of them
}
