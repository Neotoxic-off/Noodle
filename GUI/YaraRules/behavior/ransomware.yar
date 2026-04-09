// severity: dangerous
rule Behavior_Ransomware_FileOps {
    meta:
        description = "File enumeration + encryption + delete — ransomware behavior"
    strings:
        $find_a = "FindFirstFileA" fullword ascii
        $find_w = "FindFirstFileW" fullword ascii
        $del_a  = "DeleteFileA" fullword ascii
        $del_w  = "DeleteFileW" fullword ascii
        $enc    = "CryptEncrypt" fullword ascii
        $bcrypt = "BCryptEncrypt" fullword ascii
    condition:
        ($find_a or $find_w) and ($del_a or $del_w) and ($enc or $bcrypt)
}

// severity: dangerous
rule Behavior_Ransomware_Note {
    meta:
        description = "Ransom note strings embedded in binary"
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase ascii
        $note2 = "YOUR PERSONAL FILES ARE ENCRYPTED" nocase ascii
        $note3 = "README_DECRYPT" nocase ascii
        $note4 = "HOW_TO_DECRYPT" nocase ascii
        $note5 = "RECOVER_FILES" nocase ascii
        $note6 = "FILES_ENCRYPTED" nocase ascii
        $btc   = "bitcoin" nocase ascii
        $tor   = ".onion" ascii
        $ext1  = ".encrypted" nocase ascii
        $ext2  = ".locked" nocase ascii
        $ext3  = ".crypt" nocase ascii
    condition:
        any of ($note1, $note2, $note3, $note4, $note5, $note6)
        or ($tor and ($btc or any of ($ext1, $ext2, $ext3)))
}

// severity: dangerous
rule Behavior_Ransomware_ShadowDelete {
    meta:
        description = "Shadow copy deletion — ransomware removing backups"
    strings:
        $vss1 = "vssadmin delete shadows" nocase ascii
        $vss2 = "Win32_ShadowCopy" ascii
        $vss3 = "vssadmin.exe" ascii nocase
        $wmic_vss = "WMIC shadowcopy delete" nocase ascii
        $bcde = "bcdedit /set recoveryenabled no" nocase ascii
    condition:
        any of them
}
