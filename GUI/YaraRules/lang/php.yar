// severity: safe
rule Lang_PHP {
    meta:
        description = "PHP binary or bundled executable (Micro, php-cgi, WinPHP)"
    strings:
        $init   = "php_module_startup" ascii
        $sapi   = "PHP_SAPI" ascii
        $zend   = "Zend Engine" ascii
        $zend2  = "zend_execute" ascii
        $phpini = "php.ini" ascii nocase
    condition:
        2 of them
}
