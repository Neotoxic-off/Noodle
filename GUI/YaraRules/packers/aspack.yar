// severity: dangerous
rule Packer_ASPack {
    meta:
        description = "ASPack compressed binary — .aspack section or decompression stub detected"
    strings:
        $section = ".aspack" ascii
        $asdata  = ".adata" ascii
        $stub    = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? }
        $asstr   = "ASPack" ascii
    condition:
        $section or $asdata or $stub or $asstr
}
