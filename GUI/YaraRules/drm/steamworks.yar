// severity: safe
rule DRM_Steamworks {
    meta:
        description = "Valve Steam / Steamworks SDK integration"
    strings:
        $sw1 = "steam_api.dll" ascii nocase
        $sw2 = "steam_api64.dll" ascii nocase
        $sw3 = "SteamAPI_Init" ascii
        $sw4 = "SteamAPI_RunCallbacks" ascii
        $sw5 = "ISteamClient" ascii
        $sw6 = "CSteamworks" ascii nocase
        $sw7 = "steam.exe" ascii nocase
        $sw8 = "Steamworks" ascii nocase
        $appid = "steam_appid.txt" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule DRM_EpicOnlineServices {
    meta:
        description = "Epic Online Services / Epic Games SDK"
    strings:
        $eos1 = "EOSSDK" ascii
        $eos2 = "EOS_Initialize" ascii
        $eos3 = "EOS_Platform_Create" ascii
        $eos4 = "Epic Online Services" ascii nocase
        $eos5 = "EpicGames" ascii nocase
        $eos6 = "EOSAntiCheat" ascii nocase
        $eos7 = "EOS_EResult" ascii
    condition:
        2 of them
}

// severity: safe
rule DRM_GOG_Galaxy {
    meta:
        description = "GOG Galaxy SDK integration"
    strings:
        $gog1 = "GalaxyApi" ascii
        $gog2 = "GOG.COM" ascii nocase
        $gog3 = "galaxy.dll" ascii nocase
        $gog4 = "galaxy64.dll" ascii nocase
        $gog5 = "InitAsync" ascii
        $gog6 = "IGalaxy" ascii
    condition:
        2 of them
}
