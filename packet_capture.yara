rule packet_capture {
    meta:
        description = "look for packet capture file references by sniffing lan netowrk traffic"
        version = "0.1"
    strings:
        $s1 = "packet.dll" nocase
        $s2 = "npf.sys" nocase
        $s3 = "winpcap.dll" nocase
        $s4 = "wpcap.dll" nocase
    condition:
        any of them
}
