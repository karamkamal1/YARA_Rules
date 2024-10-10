rule ftp_log {
    meta:
        description = "Inspect FTP server logs"
        version = "0.1"
    strings:
        $s1 = "honeypotuser" nocase
    condition:
        any of them
}
