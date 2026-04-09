// severity: safe
rule Lang_Swift {
    meta:
        description = "Swift binary — Swift runtime symbols"
    strings:
        $retain  = "swift_retain" ascii
        $release = "swift_release" ascii
        $lib     = "libswift" ascii
        $core    = "SwiftCore" ascii
        $stdlib  = "Swift.stdlib" ascii
    condition:
        2 of them
}
