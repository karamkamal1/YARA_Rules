rule msf_venom {
    meta:
        description = "Detects the use of msfvenom"
        version = "0.1"
    strings:
        $s1 = "msfvenom"
        $s2 = "Metaploit Payload"
        $s3 = "Meterpreter"

    condition:
        any of them
        
}