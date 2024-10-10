/*
    Search for nmap strings. 
*/
rule detect_nmap {
    meta:
        description = "Detects references to nmap in files"
        version = "0.1"
    strings:
        $nmapStrings = /nmap|nmap.org|zenmap/i
    condition:
        any of them
}