rule rat_webcam{
    meta:
        descritpion = "Detects the use of a webcam by a RAT"
        version = "0.1"
    strings:
        $f1 = "avicap32.dll" nocase
        $c1 = "capCreateCaptureWindow" nocase
    condition:
        all of them
}