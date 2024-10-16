rule key_log {
    meta:
        description = "Detects Commands related to keystroke logging and keyboard"
        version = "0.1"
    strings:
        $f1 = "User32.dll" nocase
        $c1 = "GetAsyncKeyState"
        $c2 = "GetKeyState"
        $c3 = "MapVirtualKey"
        $c4 = "GetKeyboardType"

    condition:
        $f1 and 1 of ($c*)
}
