rule apache_log {
    meta:
        Description = "Inspect Apache Logs"
    strings:
        $s1 = "http:"
    condition:
        any of them
}
