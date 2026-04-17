// severity: safe
rule Physics_Havok {
    meta:
        description = "Havok physics/animation middleware"
    strings:
        $hk1 = "Havok" ascii nocase fullword
        $hk2 = "hkpWorld" ascii
        $hk3 = "hkaAnimationBinding" ascii
        $hk4 = "hkMemoryRouter" ascii
        $hk5 = "hkBaseSystem" ascii
        $hk6 = "Havok Content Tools" ascii nocase
        $hk7 = "hkDefaultMemoryRouter" ascii
    condition:
        2 of them
}
