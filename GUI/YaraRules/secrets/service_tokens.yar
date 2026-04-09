// severity: dangerous
rule Credential_Slack_Token {
    meta:
        description = "Slack API token (xoxb / xoxp / xoxa / xoxs)"
    strings:
        $xoxb = "xoxb-" ascii
        $xoxp = "xoxp-" ascii
        $xoxa = "xoxa-" ascii
        $xoxs = "xoxs-" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_Stripe {
    meta:
        description = "Stripe live secret or restricted key"
    strings:
        $sk  = "sk_live_" ascii
        $rk  = "rk_live_" ascii
        $pk  = "pk_live_" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_Twilio {
    meta:
        description = "Twilio account SID or auth token"
    strings:
        $ac   = "AC" ascii
        $sid  = "TWILIO_ACCOUNT_SID" ascii
        $auth = "TWILIO_AUTH_TOKEN" ascii
    condition:
        $sid or $auth
}

// severity: dangerous
rule Credential_SendGrid {
    meta:
        description = "SendGrid API key (SG. prefix)"
    strings:
        $sg = "SG." ascii
    condition:
        $sg
}

// severity: dangerous
rule Credential_NPM_Token {
    meta:
        description = "npm automation or publish token"
    strings:
        $npm = "npm_" ascii
    condition:
        $npm
}

// severity: dangerous
rule Credential_Telegram_Bot {
    meta:
        description = "Telegram Bot API URL hardcoded"
    strings:
        $api = "api.telegram.org/bot" ascii
    condition:
        $api
}

// severity: dangerous
rule Credential_Mailgun {
    meta:
        description = "Mailgun API key"
    strings:
        $mg1 = "MAILGUN_API_KEY" ascii
        $mg2 = "api.mailgun.net" ascii
        $mg3 = "key-" ascii
    condition:
        2 of them
}

// severity: dangerous
rule Credential_Pusher {
    meta:
        description = "Pusher app secret or key"
    strings:
        $psh1 = "PUSHER_APP_SECRET" ascii
        $psh2 = "pusher.com" ascii
    condition:
        2 of them
}

// severity: dangerous
rule Credential_Paypal {
    meta:
        description = "PayPal live client ID or secret"
    strings:
        $pp1 = "PAYPAL_CLIENT_SECRET" ascii
        $pp2 = "paypal_secret" ascii nocase
        $pp3 = "api.paypal.com" ascii
    condition:
        any of them
}
