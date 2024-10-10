
/*
    Inspect IIS Logs
*/

rule iis_log {
    meta:
        description = "Inspect IIS Logs"
    strings:
        $sl = "login.aspx"
    condition:
        any of them
}
