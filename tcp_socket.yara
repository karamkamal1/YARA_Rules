/*
    tcp_socket.yara - YARA rule to detect TCP over RAW socket
*/


rule tcp_socket {
    meta:
        description = "TCP over RAW socket"
        version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Wsock32.dll" nocase
        $s3 = "WSASocket"
        $s4 = "WSAStartup"
        $s5 = "WSACleanup"
        $s6 = "WSARecv"
        $s7 = "WSASend"
        $s8 = "WSAConnect"
        $s9 = "socket"
        $s10 = "send"
        $s11 = "connect"
        $s12 = "closesocket"

    condition:
        1 of ($f*) and 2 of ($s*)
}