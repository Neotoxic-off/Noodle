// severity: suspicious
rule Crypto_WindowsCryptAPI {
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
rule Crypto_BCryptAPI {
    meta:
        description = "Imports BCrypt API — modern Windows encryption, may be used for ransomware or C2"
    strings:
        $enc  = "BCryptEncrypt" fullword ascii
        $dec  = "BCryptDecrypt" fullword ascii
        $open = "BCryptOpenAlgorithmProvider" fullword ascii
        $gen  = "BCryptGenerateKeyPair" fullword ascii
        $hash = "BCryptCreateHash" fullword ascii
    condition:
        any of them
}
