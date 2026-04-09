// severity: dangerous
rule Behavior_Keylogger_GlobalHook {
    meta:
        description = "SetWindowsHookEx — global keyboard or mouse hook"
    strings:
        $hookA  = "SetWindowsHookExA" fullword ascii
        $hookW  = "SetWindowsHookExW" fullword ascii
    condition:
        $hookA or $hookW
}

// severity: dangerous
rule Behavior_Keylogger_AsyncPoll {
    meta:
        description = "GetAsyncKeyState / GetKeyState — polling-based keylogger"
    strings:
        $async   = "GetAsyncKeyState" fullword ascii
        $state   = "GetKeyState" fullword ascii
        $kbstate = "GetKeyboardState" fullword ascii
        $hotkey  = "RegisterHotKey" fullword ascii
        $mapA    = "MapVirtualKeyA" fullword ascii
        $mapW    = "MapVirtualKeyW" fullword ascii
    condition:
        any of them
}

// severity: dangerous
rule Behavior_Keylogger_RawInput {
    meta:
        description = "RegisterRawInputDevices — raw keyboard input capture"
    strings:
        $raw  = "RegisterRawInputDevices" fullword ascii
        $get  = "GetRawInputData" fullword ascii
    condition:
        any of them
}
