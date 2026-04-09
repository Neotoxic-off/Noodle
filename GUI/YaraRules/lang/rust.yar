// severity: safe
rule Lang_Rust {
    meta:
        description = "Rust binary — panic handler or standard library symbols"
    strings:
        $unwind = "rust_begin_unwind" ascii
        $panic  = "rust_panic" ascii
        $dealloc = "__rust_dealloc" ascii
        $alloc  = "__rust_alloc" ascii
        $eh     = "__rust_eh_personality" ascii
        $core   = "core::panicking" ascii
        $std    = "std::rt::lang_start" ascii
    condition:
        any of them
}
