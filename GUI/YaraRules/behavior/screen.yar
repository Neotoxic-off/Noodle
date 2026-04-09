// severity: suspicious
rule Behavior_ScreenCapture {
    meta:
        description = "GDI screen capture — binary may take desktop screenshots"
    strings:
        $bitblt  = "BitBlt" fullword ascii
        $print   = "PrintWindow" fullword ascii
        $getdc   = "GetDC" fullword ascii
        $compbmp = "CreateCompatibleBitmap" fullword ascii
        $compdc  = "CreateCompatibleDC" fullword ascii
    condition:
        $bitblt and ($getdc or $compbmp or $compdc)
}

// severity: suspicious
rule Behavior_WebcamAccess {
    meta:
        description = "Webcam / video capture access via DirectShow or MediaFoundation"
    strings:
        $ds1   = "capCreateCaptureWindow" ascii
        $mf1   = "MFCreateSourceReaderFromMediaSource" ascii
        $vid1  = "VideoCaptureDevice" ascii
        $vid2  = "CLSID_VideoInputDeviceCategory" ascii
        $icap  = "IVideoWindow" ascii
    condition:
        any of them
}

// severity: suspicious
rule Behavior_MicrophoneAccess {
    meta:
        description = "Microphone access via DirectSound or WASAPI"
    strings:
        $wasapi  = "IAudioCaptureClient" ascii
        $dsound  = "DirectSoundCapture" ascii
        $mmrec   = "waveInOpen" fullword ascii
        $mmrec2  = "waveInStart" fullword ascii
        $mic     = "CLSID_AudioInputDeviceCategory" ascii
    condition:
        any of them
}
