// severity: suspicious
rule Behavior_Crypto_WinCryptAPI {
    meta:
        description = "Imports Windows CryptoAPI — may encrypt data (ransomware, C2, dropper)"
    strings:
        $enc  = "CryptEncrypt" fullword ascii
        $dec  = "CryptDecrypt" fullword ascii
        $acqA = "CryptAcquireContextA" fullword ascii
        $acqW = "CryptAcquireContextW" fullword ascii
        $hash = "CryptCreateHash" fullword ascii
        $key  = "CryptGenKey" fullword ascii
        $imp  = "CryptImportKey" fullword ascii
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Crypto_BCrypt {
    meta:
        description = "Imports BCrypt API — modern Windows encryption"
    strings:
        $enc  = "BCryptEncrypt" fullword ascii
        $dec  = "BCryptDecrypt" fullword ascii
        $open = "BCryptOpenAlgorithmProvider" fullword ascii
        $gen  = "BCryptGenerateKeyPair" fullword ascii
        $hash = "BCryptCreateHash" fullword ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_Crypto_OpenSSL {
    meta:
        description = "Imports OpenSSL functions — binary uses TLS or cryptographic operations"
    strings:
        $ssl1 = "SSL_CTX_new" ascii
        $ssl2 = "SSL_connect" ascii
        $ssl3 = "EVP_EncryptInit" ascii
        $ssl4 = "RSA_generate_key" ascii
        $ssl5 = "AES_encrypt" ascii
        $ssl6 = "libssl" ascii nocase
        $ssl7 = "libcrypto" ascii nocase
    condition:
        2 of them
}

// severity: suspicious
rule Behavior_Crypto_CRC_XOR {
    meta:
        description = "Common XOR / rolling-XOR pattern — simple obfuscation or encryption"
    strings:
        $xorcmd = "xor eax, eax" ascii nocase
        $rc4a   = "RC4" fullword ascii
        $rc4b   = "rc4_" ascii
        $chacha = "ChaCha20" ascii
        $salsa  = "Salsa20" ascii
    condition:
        any of them
}
