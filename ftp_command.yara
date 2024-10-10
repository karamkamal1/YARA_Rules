/*
    Detect FTP command references
*/

rule FTP_com {
    meta:
        description = "Find FTP command references"
        version = "0.1"
    strings:
        $s1 = "USER"
        $s2 = "PASS"
        $s3 = "RETR"
        $s4 = "STOR"
    condition:
        any of them
}