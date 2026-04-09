// severity: safe
rule Framework_Flutter {
    meta:
        description = "Flutter / Dart binary"
    strings:
        $dart1  = "dart_" ascii
        $dart2  = "Dart_" ascii
        $dartvm = "DartVM" ascii
        $flutter = "FlutterEngine" ascii
        $flutter2 = "flutter_" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_ReactNative {
    meta:
        description = "React Native Windows desktop or mobile binary"
    strings:
        $rn1 = "reactnative" ascii nocase
        $rn2 = "React.createElement" ascii
        $rn3 = "ReactNativeHost" ascii
        $hermes = "HermesRuntime" ascii
        $jsi    = "facebook::jsi" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_Xamarin {
    meta:
        description = "Xamarin / MAUI mobile framework binary"
    strings:
        $xam1 = "Xamarin" ascii
        $xam2 = "mono-android" ascii nocase
        $xam3 = "Xamarin.Forms" ascii
        $maui = "Microsoft.Maui" ascii
    condition:
        2 of them
}
