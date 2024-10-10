/*
    Look for references to drop spots in the registry
*/


rule dropper{
    meta : 
        description = "Find drop spot references"
        version = "0.1"
    strings:
        $r1 = "Current\\Version\\Run" nocase wide ascii
        $r2 = "CurrentControlSet\\Services" nocase wide ascii
        $r3 = "Programs\\Startup" nocase wide ascii
        $s1 = "%temp%" nocase wide ascii
        $s2 = "allusersprofile" nocase wide ascii
    condition:
        any of them

}