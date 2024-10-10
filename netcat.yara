/*
    Look for references of netcat used as a reverse shell
*/

rule netcat_reverse_shell{
    meta:
        description = "Detects references to netcat reverse shell"
        version = "0.1"
    strings:
        $p1 = "nc.exe"
        $p2 = "ncat.exe"
        $p3 = "ncat"
        $s1 = "reverse shell"
        $s2 = "nc -i -p"
        $s3 = "ncat -i -p"
        $s4 = "..exec cmd.exe"
    condition:
        any of ($p*) and any of ($s*)
}