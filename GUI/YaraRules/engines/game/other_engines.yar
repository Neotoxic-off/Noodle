// severity: safe
rule Engine_SDL {
    meta:
        description = "SDL (Simple DirectMedia Layer) game/app binary"
    strings:
        $sdl1 = "SDL_Init" ascii
        $sdl2 = "SDL_CreateWindow" ascii
        $sdl3 = "SDL_RenderPresent" ascii
        $sdl4 = "SDL_PollEvent" ascii
        $sdl5 = "SDL2.dll" ascii nocase
        $sdl6 = "SDL_mixer" ascii
        $sdl7 = "SDL_ttf" ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_SFML {
    meta:
        description = "SFML (Simple and Fast Multimedia Library) binary"
    strings:
        $sfml1 = "sfml-system" ascii nocase
        $sfml2 = "sfml-window" ascii nocase
        $sfml3 = "sfml-graphics" ascii nocase
        $sfml4 = "sfml-audio" ascii nocase
        $sfml5 = "sfml-network" ascii nocase
        $sfml6 = "sf::RenderWindow" ascii
        $sfml7 = "SFML" ascii fullword
    condition:
        2 of them
}

// severity: safe
rule Engine_MonoGame {
    meta:
        description = "MonoGame / XNA framework game binary"
    strings:
        $mg1 = "MonoGame" ascii nocase
        $mg2 = "Microsoft.Xna.Framework" ascii
        $mg3 = "XNA Game Studio" ascii nocase
        $mg4 = "GraphicsDeviceManager" ascii
        $mg5 = "SpriteBatch" ascii
        $mg6 = "ContentManager" ascii
        $xnb = ".xnb" ascii fullword
    condition:
        2 of them
}

// severity: safe
rule Engine_Torque {
    meta:
        description = "Torque game engine binary (Torque3D, T2D)"
    strings:
        $t1 = "Torque3D" ascii nocase
        $t2 = "Torque2D" ascii nocase
        $t3 = "GarageGames" ascii nocase
        $t4 = "TorqueScript" ascii nocase
        $t5 = "GuiCanvas" ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_Pygame {
    meta:
        description = "Pygame-based game binary (Python + SDL)"
    strings:
        $pg1 = "pygame" ascii nocase
        $pg2 = "pygame.display" ascii nocase
        $pg3 = "pygame.mixer" ascii nocase
        $pg4 = "pygame.sprite" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Engine_libGDX {
    meta:
        description = "libGDX Java/JVM game framework"
    strings:
        $lg1 = "com.badlogic.gdx" ascii
        $lg2 = "libgdx" ascii nocase
        $lg3 = "GdxNativesLoader" ascii
        $lg4 = "ApplicationAdapter" ascii
        $lg5 = "SpriteBatch" ascii
        $lg6 = "gdx-backend" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Engine_Love2D {
    meta:
        description = "LOVE2D Lua game engine binary"
    strings:
        $love1 = "love2d" ascii nocase
        $love2 = "love.graphics" ascii
        $love3 = "love.update" ascii
        $love4 = "love.draw" ascii
        $love5 = "LOVE " ascii
        $love6 = "love.run" ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_Construct {
    meta:
        description = "Construct 2/3 game engine exported binary"
    strings:
        $c1 = "Construct" ascii nocase fullword
        $c2 = "Scirra" ascii nocase
        $c3 = "c3runtime" ascii nocase
        $c4 = "IRuntime" ascii
        $c5 = "construct.net" ascii nocase
    condition:
        2 of them
}
