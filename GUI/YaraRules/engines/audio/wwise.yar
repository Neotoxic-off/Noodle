// severity: safe
rule Audio_Wwise {
    meta:
        description = "Audiokinetic Wwise audio middleware"
    strings:
        $ww1 = "Audiokinetic" ascii nocase
        $ww2 = "Wwise" ascii nocase
        $ww3 = "AkSoundEngine" ascii
        $ww4 = "AK::SoundEngine" ascii
        $ww5 = "AkInitSettings" ascii
        $ww6 = "AK_Success" ascii
        $ww7 = "AkBank" ascii
        $ww8 = "WwiseProjectDatabase" ascii
    condition:
        2 of them
}
