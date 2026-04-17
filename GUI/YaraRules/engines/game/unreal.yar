// severity: safe
rule Engine_UnrealEngine {
    meta:
        description = "Unreal Engine game binary (UE4/UE5)"
    strings:
        $ue1  = "Unreal Engine" ascii nocase
        $ue2  = "UE4Game" ascii
        $ue3  = "UE5Game" ascii
        $ue4  = "Epic Games" ascii
        $ue5  = "GEngine" ascii
        $ue6  = "FUObjectArray" ascii
        $ue7  = "UObject::ProcessEvent" ascii
        $pak  = "CookedGameInfo" ascii
        $pak2 = ".pak" ascii fullword
        $uasset = ".uasset" ascii
        $umap   = ".umap" ascii
    condition:
        2 of ($ue1, $ue2, $ue3, $ue4, $ue5, $ue6, $ue7)
        or (($pak or $pak2) and ($uasset or $umap))
}

// severity: safe
rule Engine_UnrealEngine3 {
    meta:
        description = "Unreal Engine 3 binary (UDK/UE3 era)"
    strings:
        $ue3_1 = "UnrealScript" ascii
        $ue3_2 = "Script/Core.u" ascii
        $ue3_3 = "GGameName" ascii
        $ue3_4 = "UPackage" ascii
        $ue3_5 = "UFunction" ascii
    condition:
        2 of them
}
