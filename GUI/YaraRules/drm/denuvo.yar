// severity: safe
rule DRM_Denuvo {
    meta:
        description = "Denuvo anti-tamper DRM (common in AAA games)"
    strings:
        $dv1 = "denuvo" ascii nocase
        $dv2 = "Denuvo Software Solutions" ascii nocase
        $dv3 = "denuvo-auth" ascii nocase
        $dv4 = "denuvo.com" ascii nocase
        $dv5 = "trigger_bypass" ascii nocase
        $dv6 = "emu64" ascii nocase
        $dv7 = "Denuvo Anti-Tamper" ascii nocase
    condition:
        any of them
}

// severity: safe
rule DRM_Denuvo_Anti_Cheat {
    meta:
        description = "Denuvo Anti-Cheat kernel driver artifacts"
    strings:
        $ac1 = "denuvo-anti-cheat" ascii nocase
        $ac2 = "Irdeto" ascii nocase
        $ac3 = "DenuvoAC" ascii nocase
    condition:
        any of them
}
