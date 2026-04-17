// severity: safe
rule DB_SQLite_Library {
    meta:
        description = "SQLite embedded database library"
    strings:
        $sqlite_magic = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 }
        $sq1 = "sqlite3_open" ascii
        $sq2 = "sqlite3_exec" ascii
        $sq3 = "sqlite3_prepare" ascii
        $sq4 = "sqlite3_step" ascii
        $sq5 = "sqlite3.dll" ascii nocase
        $sq6 = "SQLite version" ascii nocase
    condition:
        $sqlite_magic or 3 of ($sq1, $sq2, $sq3, $sq4, $sq5, $sq6)
}

// severity: safe
rule DB_LevelDB {
    meta:
        description = "LevelDB / RocksDB embedded key-value store"
    strings:
        $lv1 = "leveldb" ascii nocase
        $lv2 = "rocksdb" ascii nocase
        $lv3 = "LevelDB" ascii
        $lv4 = "RocksDB" ascii
        $lv5 = "CURRENT" ascii fullword
        $lv6 = "MANIFEST" ascii fullword
        $lv7 = "leveldb.BytewiseComparator" ascii
    condition:
        2 of them
}
