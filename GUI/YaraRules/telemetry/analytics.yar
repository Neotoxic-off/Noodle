// severity: safe
rule Telemetry_GoogleAnalytics {
    meta:
        description = "Google Analytics / Firebase SDK integration"
    strings:
        $ga1 = "google-analytics.com" ascii nocase
        $ga2 = "GoogleAnalytics" ascii nocase
        $ga3 = "FirebaseAnalytics" ascii nocase
        $ga4 = "com.google.firebase" ascii nocase
        $ga5 = "gtag" ascii nocase fullword
        $ga6 = "UA-" ascii
        $ga7 = "G-" ascii fullword
        $ga8 = "firebase_app_id" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_Sentry {
    meta:
        description = "Sentry error tracking SDK"
    strings:
        $sn1 = "sentry.io" ascii nocase
        $sn2 = "SentrySDK" ascii nocase
        $sn3 = "sentry-sdk" ascii nocase
        $sn4 = "captureException" ascii nocase
        $sn5 = "captureMessage" ascii nocase
        $sn6 = "SentryClient" ascii nocase
        $sn7 = "dsn=" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_Mixpanel {
    meta:
        description = "Mixpanel analytics SDK"
    strings:
        $mx1 = "mixpanel" ascii nocase
        $mx2 = "Mixpanel" ascii
        $mx3 = "api.mixpanel.com" ascii nocase
        $mx4 = "mixpanel_token" ascii nocase
        $mx5 = "track_event" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_Amplitude {
    meta:
        description = "Amplitude analytics SDK"
    strings:
        $am1 = "amplitude" ascii nocase fullword
        $am2 = "api.amplitude.com" ascii nocase
        $am3 = "AmplitudeClient" ascii nocase
        $am4 = "amplitude_api_key" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Telemetry_Datadog {
    meta:
        description = "Datadog APM / monitoring SDK"
    strings:
        $dd1 = "datadoghq.com" ascii nocase
        $dd2 = "DatadogAgent" ascii nocase
        $dd3 = "dd-trace" ascii nocase
        $dd4 = "DD_AGENT_HOST" ascii
        $dd5 = "dogstatsd" ascii nocase
    condition:
        2 of them
}
