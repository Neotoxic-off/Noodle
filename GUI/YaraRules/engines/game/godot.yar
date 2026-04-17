// severity: safe
rule Engine_Godot {
    meta:
        description = "Godot game engine binary"
    strings:
        $godot1 = "Godot Engine" ascii
        $godot2 = "godot" ascii fullword nocase
        $godot3 = "GodotSharp" ascii
        $godot4 = "GDScript" ascii
        $godot5 = "GDNative" ascii
        $godot6 = "GDExtension" ascii
        $pck    = ".pck" ascii fullword
        $tres   = ".tres" ascii
        $tscn   = ".tscn" ascii
        $gdscript = ".gd" ascii fullword
    condition:
        2 of ($godot1, $godot2, $godot3, $godot4, $godot5, $godot6)
        or ($pck and any of ($tres, $tscn, $gdscript))
}
