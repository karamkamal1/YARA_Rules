/* 
    References to wndows network commands
*/

rule net_cmd{
    meta:
        description = "Windows Network Commands"
        version = "0.1"
    strings:
        $sc1 = "net use" nocase
        $sc2 = "net view" nocase
        $sc3 = "net user" nocase
        $sc4 = "net localgroup" nocase
        $sc5 = "net group" nocase
        $sc6 = "net share" nocase
        $sc7 = "net start" nocase
        $sc8 = "net stop" nocase
        $sc9 = "net send" nocase
    condition:
        any of them
}