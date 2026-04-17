// severity: safe
rule Engine_idTech {
    meta:
        description = "id Software id Tech engine binary (Doom, Quake, RAGE)"
    strings:
        $id1  = "id Software" ascii nocase
        $id2  = "idTech" ascii nocase
        $id3  = "Carmack" ascii
        $id4  = "Bethesda Softworks" ascii nocase
        $id5  = "id_aa64" ascii
        $pk3  = ".pk3" ascii fullword
        $pk4  = ".pk4" ascii fullword
        $wad  = "IWAD" ascii
        $wad2 = "PWAD" ascii
        $bfg  = "idLib" ascii
        $rage = "MegaTexture" ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_idTech_Quake {
    meta:
        description = "Quake engine derived binary (Quake 1-3, Darkplaces, etc.)"
    strings:
        $q1 = "Quake" ascii nocase fullword
        $q2 = "quakec" ascii nocase
        $q3 = "progs.dat" ascii nocase
        $q4 = "sv_gamedir" ascii
        $q5 = "SV_SpawnServer" ascii
        $q6 = "Host_Error" ascii
    condition:
        2 of them
}
