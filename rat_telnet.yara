/*
    Looks for signs that indicates telnet server is enabled
*/

rule rat_telnet {
    meta:
        description = "Remote Access Tool using/enabled by Telnet server"
        version = "0.1"
    strings:
        $s1 = "software\\microsoft\\telnetserver" 
    condition:
        $s1
}