/*
    UDP Socket detection
    Notte: Could be Client or Server
*/


rule network_UDP {
    meta:
        description = "Detect UDP network communication"
        version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $f3 = "System.Net" nocase
        $c0 = "WSAStartup"
        $c1 = "sendto"
        $c2 = "recvfrom"
        $c3 = "WSASendTo"
        $c4 = "WSARecvFrom"
        $c5 = "UdpClient"
    condition:
        (($f1 or $f2) and 2 of ($sc*) or ($f3 and $c5))

        
}