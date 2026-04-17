// severity: safe
rule DB_Redis_Client {
    meta:
        description = "Redis client library usage in binary"
    strings:
        $rd1 = "redis" ascii nocase fullword
        $rd2 = "hiredis" ascii nocase
        $rd3 = "RedisClient" ascii nocase
        $rd4 = "HSET" ascii fullword
        $rd5 = "HGET" ascii fullword
        $rd6 = "LPUSH" ascii fullword
        $rd7 = "RPOP" ascii fullword
        $rd8 = "redis.io" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule DB_MongoDB_Client {
    meta:
        description = "MongoDB client / driver usage"
    strings:
        $mg1 = "mongoclient" ascii nocase
        $mg2 = "mongodb" ascii nocase fullword
        $mg3 = "bson_new" ascii nocase
        $mg4 = "mongoc_client_new" ascii
        $mg5 = "mongoc_collection_find" ascii
        $mg6 = "MongoDB" ascii
    condition:
        2 of them
}

// severity: safe
rule DB_PostgreSQL_Client {
    meta:
        description = "PostgreSQL client / libpq usage"
    strings:
        $pg1 = "libpq.dll" ascii nocase
        $pg2 = "PQconnectdb" ascii
        $pg3 = "PQexec" ascii
        $pg4 = "PostgreSQL" ascii nocase
        $pg5 = "pg_connect" ascii nocase
        $pg6 = "PQfinish" ascii
    condition:
        2 of them
}
