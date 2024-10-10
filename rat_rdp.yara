/*
    Search for RDP references in the registry paths, values, and commands
*/

rule rat_rdp {
    meta:
        description = "Remote Access through RDP"
        version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $r2 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}