// severity: dangerous
rule Credential_PrivateKey_RSA {
    meta:
        description = "Embedded RSA private key (PEM)"
    strings:
        $hdr = "-----BEGIN RSA PRIVATE KEY-----" ascii
    condition:
        $hdr
}

// severity: dangerous
rule Credential_PrivateKey_EC {
    meta:
        description = "Embedded EC private key (PEM)"
    strings:
        $hdr = "-----BEGIN EC PRIVATE KEY-----" ascii
    condition:
        $hdr
}

// severity: dangerous
rule Credential_PrivateKey_Generic {
    meta:
        description = "Embedded PKCS#8 private key (PEM)"
    strings:
        $hdr = "-----BEGIN PRIVATE KEY-----" ascii
    condition:
        $hdr
}

// severity: dangerous
rule Credential_PrivateKey_OpenSSH {
    meta:
        description = "Embedded OpenSSH private key"
    strings:
        $hdr = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        $hdr
}

// severity: dangerous
rule Credential_PrivateKey_PGP {
    meta:
        description = "Embedded PGP private key block"
    strings:
        $hdr = "-----BEGIN PGP PRIVATE KEY BLOCK-----" ascii
    condition:
        $hdr
}

// severity: dangerous
rule Credential_Certificate_PKCS12 {
    meta:
        description = "Embedded PKCS#12 / PFX certificate with private key"
    strings:
        $pfx  = ".pfx" ascii
        $p12  = ".p12" ascii
        $pkcs = "PKCS12" ascii
    condition:
        2 of them
}
