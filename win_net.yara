/*
    References to wndows network commands
*/

rule win_net {
    meta:
        description = "Windows Network Commands"
        version = "0.1"
    strings:
        $s1 = "ping" nocase
        $s2 = "pathping" nocase
        $s3 = "tracert" nocase
        $s4 = "netstat" nocase
        $s5 = "nslookup" nocase
        $s6 = "route print" nocase
    condition:
        any of them
}