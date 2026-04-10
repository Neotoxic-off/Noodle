// severity: safe
rule Lang_Perl_PAR {
    meta:
        description = "Perl bundled with PAR::Packer"
    strings:
        $par1   = "PAR::Packer" ascii
        $par2   = "par.pl" nocase ascii
        $parenv = "PAR_TEMP" ascii
    condition:
        any of them
}

// severity: safe
rule Lang_Perl_Runtime {
    meta:
        description = "Perl binary — stable Perl embedding C API present"
    strings:
        // Stable Perl embedding C API (unchanged across Perl 5.x versions)
        $alloc    = "perl_alloc" ascii
        $constr   = "perl_construct" ascii
        $run      = "perl_run" ascii
        $destruct = "perl_destruct" ascii
        $free     = "perl_free" ascii
        $newxs    = "newXS" ascii
        $bootsub  = "boot_DynaLoader" ascii
    condition:
        2 of them
}
