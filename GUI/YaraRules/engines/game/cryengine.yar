// severity: safe
rule Engine_CryEngine {
    meta:
        description = "CryEngine / CRYENGINE game binary"
    strings:
        $cry1 = "CryEngine" ascii nocase
        $cry2 = "CrySystem.dll" ascii nocase
        $cry3 = "CryAction.dll" ascii nocase
        $cry4 = "Cry3DEngine" ascii
        $cry5 = "CryRender" ascii
        $cry6 = "CryPhysics" ascii
        $cry7 = "CryInput" ascii
        $lmb  = "Lumberyard" ascii
        $o3de = "O3DE" ascii
        $crytif = ".cry" ascii fullword
    condition:
        2 of them
}

// severity: safe
rule Engine_Frostbite {
    meta:
        description = "DICE Frostbite engine binary (EA games)"
    strings:
        $fb1 = "Frostbite" ascii nocase
        $fb2 = "FrostEd" ascii
        $fb3 = "DICE" ascii
        $fb4 = "FBNet" ascii
        $fb5 = "EAFrostbite" ascii
        $sb  = "Superbundle" ascii nocase
    condition:
        2 of them
}
