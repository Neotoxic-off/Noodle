// severity: dangerous
rule Credential_Password_EnvVar {
    meta:
        description = "Hardcoded password environment variable names in binary"
    strings:
        $p1  = "DB_PASSWORD" ascii
        $p2  = "DATABASE_PASSWORD" ascii
        $p3  = "MYSQL_PASSWORD" ascii
        $p4  = "REDIS_PASSWORD" ascii
        $p5  = "SMTP_PASSWORD" ascii
        $p6  = "POSTGRES_PASSWORD" ascii
        $p7  = "MONGO_PASSWORD" ascii
        $p8  = "SECRET_KEY" ascii
        $p9  = "APP_SECRET" ascii
        $p10 = "MASTER_KEY" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_ConnectionString {
    meta:
        description = "Database connection string with embedded credentials"
    strings:
        $jdbc  = "jdbc:mysql://" ascii nocase
        $pg    = "postgresql://" ascii nocase
        $mongo = "mongodb+srv://" ascii nocase
        $redis = "redis://:@" ascii nocase
        $amqp  = "amqp://" ascii nocase
        $mssql = "Data Source=;Initial Catalog=;User ID=" ascii nocase
    condition:
        any of them
}

// severity: dangerous
rule Credential_BasicAuth_Hardcoded {
    meta:
        description = "HTTP Basic Auth header hardcoded in binary"
    strings:
        $basic = "Authorization: Basic " ascii
        $bearer = "Authorization: Bearer " ascii
    condition:
        any of them
}
