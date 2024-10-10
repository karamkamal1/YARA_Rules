rule Suspicious_Refs {
    meta:
        description = "Detects misc suspicious references you may want to investigate"
    strings:
        $s1 = "backdoor" nocase ascii wide  
        $s2 = "virus" nocase ascii wide fullword
        $s3 = "hack" nocase ascii wide fullword
        $s4 = "exploit" nocase ascii wide
    condition:
        any of them
}
