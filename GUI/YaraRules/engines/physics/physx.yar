// severity: safe
rule Physics_NVIDIA_PhysX {
    meta:
        description = "NVIDIA PhysX physics engine"
    strings:
        $px1 = "PhysX" ascii nocase fullword
        $px2 = "nvPhysX" ascii nocase
        $px3 = "PhysX3.dll" ascii nocase
        $px4 = "PhysXCommon" ascii nocase
        $px5 = "PxCreatePhysics" ascii
        $px6 = "PxFoundation" ascii
        $px7 = "PxScene" ascii
        $px8 = "NVIDIA Corporation" ascii nocase
    condition:
        2 of them
}
