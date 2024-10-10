rule detect_P2P {
    meta:
        description = "Detects refrences to P2P communication"
        version = "0.1"
    strings:
        $p2pStrings = /torrent|p2p|peer to peer|ed2k|magnet:|shareaza/i
    condition:
        any of them
}