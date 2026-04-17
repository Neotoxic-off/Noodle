// severity: safe
rule Audio_FMOD {
    meta:
        description = "FMOD audio engine (Firelight Technologies)"
    strings:
        $fmod1 = "fmod.dll" ascii nocase
        $fmod2 = "fmodex.dll" ascii nocase
        $fmod3 = "fmodstudio.dll" ascii nocase
        $fmod4 = "FMOD_System_Create" ascii
        $fmod5 = "FMOD_Studio_System_Create" ascii
        $fmod6 = "Firelight Technologies" ascii nocase
        $fmod7 = "FMOD Studio" ascii nocase
        $fmod8 = "FMOD_RESULT" ascii
    condition:
        2 of them
}
