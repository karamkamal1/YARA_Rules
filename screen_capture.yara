/*
    Detects references to screen capture
*/


rule screen_capture {
    meta:
        description = "detects potential screen capture"
        version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt"
        $c2 = "GetDC"
    condition:
        1 of ($d*) and 1 of ($c*)
}
