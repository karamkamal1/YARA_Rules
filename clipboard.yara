/*
    Detects Windows API clipboard functions in a file
*/

rule win_clip{
    meta:
        description = "Detects Commands related to clipboard"
        version = "0.1"
    strings:
        $c1 = "OpenClipboard"
        $c2 = "GetClipboardData"
        $c3 = "SetClipboardData"
        $c4 = "CloseClipboard"
    condition:
        any of them
}