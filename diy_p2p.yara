/*
    find references to p2p.h functions
*/

rule diy_p2p {
    meta:
        description = "Communications over a P2P network"
        version = "0.1"
    strings:
        $c1 = "PeerCollab"
    condition:
        $c1
}