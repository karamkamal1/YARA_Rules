rule detect_tor {
    meta:
        description = "Detects the use of Tor"
        version = "0.1"
    strings:
        $torStrings =/onion|\.onion|torproject\.org/i 
    condition:
        any of them
}