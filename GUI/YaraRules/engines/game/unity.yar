// severity: safe
rule Engine_Unity {
    meta:
        description = "Unity game engine binary"
    strings:
        $unity1  = "UnityEngine" ascii
        $unity2  = "UnityPlayer.dll" ascii nocase
        $unity3  = "Unity Technologies" ascii
        $unity4  = "com.unity3d" ascii
        $unity5  = "UnityMain" ascii
        $mono    = "mono_jit_init" ascii
        $il2cpp  = "il2cpp_init" ascii
        $assets  = "globalgamemanagers" ascii
        $data    = "unity default resources" nocase ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_Unity_IL2CPP {
    meta:
        description = "Unity game built with IL2CPP backend (AOT compiled)"
    strings:
        $il2cpp1 = "il2cpp_init" ascii
        $il2cpp2 = "il2cpp_runtime_invoke" ascii
        $il2cpp3 = "il2cpp_resolve_icall" ascii
        $il2cpp4 = "GameAssembly.dll" ascii nocase
        $meta    = "Il2CppCodeRegistration" ascii
    condition:
        2 of them
}

// severity: safe
rule Engine_Unity_Mono {
    meta:
        description = "Unity game using Mono scripting backend"
    strings:
        $mono1 = "mono_jit_init_version" ascii
        $mono2 = "mono_domain_assembly_open" ascii
        $mono3 = "Mono JIT compiler" ascii
        $mono4 = "Assembly-CSharp.dll" ascii nocase
        $mono5 = "Managed/Assembly-CSharp" ascii nocase
    condition:
        2 of them
}
