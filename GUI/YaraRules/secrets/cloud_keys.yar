// severity: dangerous
rule Credential_AWS_AccessKey {
    meta:
        description = "AWS access key ID (AKIA/AROA/ASIA prefix) alongside AWS context"
    strings:
        // Key ID prefixes — 4 chars alone are too short; require AWS infrastructure context
        $akia     = "AKIA" ascii
        $aroa     = "AROA" ascii
        $asia     = "ASIA" ascii
        // Context strings that confirm AWS usage
        $aws_svc  = "amazonaws.com" ascii
        $aws_cred = "aws_access_key_id" nocase ascii
    condition:
        ($akia or $aroa or $asia) and ($aws_svc or $aws_cred)
}

// severity: dangerous
rule Credential_AWS_SecretKey {
    meta:
        description = "AWS secret key or session token environment variable"
    strings:
        $envkey  = "AWS_SECRET_ACCESS_KEY" ascii
        $envsess = "AWS_SESSION_TOKEN" ascii
        $confkey = "aws_secret_access_key" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_GCP_ServiceAccount {
    meta:
        description = "Google Cloud service account key — private_key_id field"
    strings:
        $svc1 = "private_key_id" ascii
        $svc2 = "service_account" ascii
        $gcp  = "googleapis.com" ascii
        $aiza = "AIza" ascii
    condition:
        ($svc1 and $svc2) or $aiza
}

// severity: dangerous
rule Credential_Azure_Keys {
    meta:
        description = "Azure storage connection string or SAS token"
    strings:
        $blob = "DefaultEndpointsProtocol=https;AccountName=" ascii
        $sas  = "SharedAccessSignature=" ascii
        $sub  = "AZURE_CLIENT_SECRET" ascii
        $conn = "azure.storage.account" nocase ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_DigitalOcean {
    meta:
        description = "DigitalOcean personal access token"
    strings:
        $dop   = "dop_v1_" ascii
        $doo   = "doo_v1_" ascii
        $dor   = "dor_v1_" ascii
        $doenv = "DIGITALOCEAN_TOKEN" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_Cloudflare {
    meta:
        description = "Cloudflare API key or token"
    strings:
        $cf1 = "CLOUDFLARE_API_KEY" ascii
        $cf2 = "CLOUDFLARE_API_TOKEN" ascii
        $cf3 = "X-Auth-Key:" ascii
        $cf4 = "X-Auth-Email:" ascii
    condition:
        2 of them
}

// severity: dangerous
rule Credential_Heroku {
    meta:
        description = "Heroku API key"
    strings:
        $her1 = "HEROKU_API_KEY" ascii
        $her2 = "heroku.com/apps" ascii
    condition:
        any of them
}
