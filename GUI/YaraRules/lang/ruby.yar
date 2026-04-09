// severity: safe
rule Lang_Ruby {
    meta:
        description = "Ruby binary or OCRA-bundled executable"
    strings:
        $ocra1  = "OCRA" ascii
        $ocra2  = "RUBYOPT" ascii
        $rubydll = "msvcrt-ruby" ascii nocase
        $rubyrt = "ruby_init" ascii
        $rubymain = "rb_main" ascii
        $gemspec = "Gemfile" ascii
    condition:
        $ocra1 or $ocra2 or $rubydll or $rubyrt or $rubymain
}
