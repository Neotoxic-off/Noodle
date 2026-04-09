// severity: dangerous
rule Packer_UPX {
    meta:
        description = "UPX packed binary — section names UPX0/UPX1 or UPX decompression stub detected"
    strings:
        $name0     = "UPX0" ascii
        $name1     = "UPX1" ascii
        $name2     = "UPX2" ascii
        $magic     = "UPX!" ascii
        $stub_x86  = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub_x64  = { 53 51 52 56 57 55 41 54 41 55 41 56 41 57 48 8D 35 }
    condition:
        ($name0 and $name1) or $magic or $stub_x86 or $stub_x64
}
