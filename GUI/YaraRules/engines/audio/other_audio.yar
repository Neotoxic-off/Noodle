// severity: safe
rule Audio_BASS {
    meta:
        description = "Un4seen BASS audio library"
    strings:
        $bass1 = "bass.dll" ascii nocase
        $bass2 = "bass_fx.dll" ascii nocase
        $bass3 = "BASS_Init" ascii
        $bass4 = "BASS_StreamCreateFile" ascii
        $bass5 = "BASS_ChannelPlay" ascii
        $bass6 = "Un4seen" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Audio_OpenAL {
    meta:
        description = "OpenAL / OpenAL Soft audio library"
    strings:
        $oal1 = "OpenAL32.dll" ascii nocase
        $oal2 = "soft_oal.dll" ascii nocase
        $oal3 = "alGenSources" ascii
        $oal4 = "alSourcePlay" ascii
        $oal5 = "alcCreateContext" ascii
        $oal6 = "alcOpenDevice" ascii
        $oal7 = "OpenAL" ascii fullword
    condition:
        2 of them
}

// severity: safe
rule Audio_MilesSound {
    meta:
        description = "Miles Sound System (RAD Game Tools) audio middleware"
    strings:
        $mss1 = "Miles Sound System" ascii nocase
        $mss2 = "mss32.dll" ascii nocase
        $mss3 = "mss64.dll" ascii nocase
        $mss4 = "AIL_init_sample" ascii
        $mss5 = "AIL_open_stream" ascii
        $mss6 = "RAD Game Tools" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Audio_XAudio2 {
    meta:
        description = "Microsoft XAudio2 / WASAPI audio API"
    strings:
        $xa1 = "XAudio2Create" ascii
        $xa2 = "IXAudio2" ascii
        $xa3 = "xaudio2.dll" ascii nocase
        $xa4 = "XAUDIO2_BUFFER" ascii
        $xa5 = "IXAudio2SourceVoice" ascii
    condition:
        2 of them
}
