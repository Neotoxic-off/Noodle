// severity: safe
rule Framework_Electron {
    meta:
        description = "Electron app — Node.js/Chromium desktop framework"
    strings:
        $asar  = "app.asar" ascii
        $napi  = "napi_create_string_utf8" ascii
        $v8    = "v8::Isolate" ascii
        $ipc   = "ipcRenderer" ascii
        $ipcm  = "ipcMain" ascii
        $bwin  = "BrowserWindow" ascii
    condition:
        2 of them
}
