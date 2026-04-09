// severity: safe
rule Lang_Perl {
    meta:
        description = "Perl binary or PAR::Packer bundled executable"
    strings:
        $par1   = "PAR::Packer" ascii
        $par2   = "par.pl" ascii nocase
        $parenv = "PAR_TEMP" ascii
        $perlrt = "perl58.dll" nocase ascii
        $perlrt2 = "perl510.dll" nocase ascii
        $perlrt3 = "perl512.dll" nocase ascii
        $perlrt4 = "perl516.dll" nocase ascii
        $perlrt5 = "perl518.dll" nocase ascii
        $perlrt6 = "perl520.dll" nocase ascii
        $perlrt7 = "perl522.dll" nocase ascii
        $perlmain = "perl_alloc" ascii
    condition:
        any of ($par1, $par2, $parenv, $perlmain) or
        any of ($perlrt, $perlrt2, $perlrt3, $perlrt4, $perlrt5, $perlrt6, $perlrt7)
}
