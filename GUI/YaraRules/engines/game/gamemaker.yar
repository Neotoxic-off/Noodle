// severity: safe
rule Engine_GameMakerStudio {
    meta:
        description = "GameMaker Studio game binary"
    strings:
        $gm1 = "GameMaker" ascii nocase
        $gm2 = "YoYo Games" ascii nocase
        $gm3 = "YoYoRunner" ascii
        $gm4 = "GMRoom" ascii
        $gm5 = "gmscript" ascii nocase
        $gm6 = "data.win" ascii nocase
        $gm7 = "YYC Runtime" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Engine_RPGMaker {
    meta:
        description = "RPG Maker game binary (MV/MZ/VX/XP)"
    strings:
        $rpg1 = "RPG Maker" ascii nocase
        $rpg2 = "RPGVXAce" ascii nocase
        $rpg3 = "RGSS3A" ascii
        $rpg4 = "RGSS2A" ascii
        $rpg5 = "Game.rgss3a" ascii nocase
        $rpg6 = "nw.js" ascii nocase
        $rpg7 = "rpg_core" ascii nocase
        $rpg8 = "rpg_managers" ascii nocase
    condition:
        2 of them
}
