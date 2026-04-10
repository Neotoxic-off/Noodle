// severity: dangerous
rule Behavior_Keylogger_GlobalHook {
    meta:
        description = "SetWindowsHookEx — global keyboard or mouse hook"
    strings:
        $hookA = "SetWindowsHookExA" fullword ascii
        $hookW = "SetWindowsHookExW" fullword ascii
    condition:
        $hookA or $hookW
}

// severity: dangerous
rule Behavior_Keylogger_AsyncPoll {
    meta:
        description = "GetAsyncKeyState — polling-based keylogger (checks key state at any time)"
    strings:
        $async = "GetAsyncKeyState" fullword ascii
    condition:
        $async
}

// severity: suspicious
rule Behavior_Keylogger_RawInput {
    meta:
        description = "RegisterRawInputDevices — raw keyboard input capture"
    strings:
        $raw = "RegisterRawInputDevices" fullword ascii
        $get = "GetRawInputData" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Keylogger_Hotkey {
    meta:
        description = "RegisterHotKey — registers a system-wide hotkey"
    strings:
        $hotkey = "RegisterHotKey" fullword ascii
    condition:
        $hotkey
}
