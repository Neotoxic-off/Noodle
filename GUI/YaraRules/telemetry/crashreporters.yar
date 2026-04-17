// severity: safe
rule Telemetry_Crashpad {
    meta:
        description = "Google Crashpad crash reporting (used by Chrome, Electron, etc.)"
    strings:
        $cp1 = "crashpad" ascii nocase fullword
        $cp2 = "crashpad_handler" ascii nocase
        $cp3 = "crashpad_client" ascii nocase
        $cp4 = "CrashpadClient" ascii nocase
        $cp5 = "crashpad.db" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_Breakpad {
    meta:
        description = "Google Breakpad crash reporting library"
    strings:
        $bp1 = "breakpad" ascii nocase fullword
        $bp2 = "google_breakpad" ascii nocase
        $bp3 = "ExceptionHandler" ascii nocase
        $bp4 = "minidump" ascii nocase
        $bp5 = "BreakpadInfo" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_BugSplat {
    meta:
        description = "BugSplat crash reporting SDK (common in games)"
    strings:
        $bs1 = "bugsplat" ascii nocase
        $bs2 = "BugSplat" ascii
        $bs3 = "bugsplat.com" ascii nocase
        $bs4 = "BugSplatDatabaseName" ascii nocase
        $bs5 = "mpSender" ascii
    condition:
        2 of them
}

// severity: safe
rule Telemetry_HockeyApp_AppCenter {
    meta:
        description = "HockeyApp / Microsoft App Center crash reporting"
    strings:
        $ha1 = "HockeyApp" ascii nocase
        $ha2 = "AppCenter" ascii nocase
        $ha3 = "appcenter.ms" ascii nocase
        $ha4 = "hockeyapp.net" ascii nocase
        $ha5 = "MSAppCenter" ascii nocase
    condition:
        2 of them
}
