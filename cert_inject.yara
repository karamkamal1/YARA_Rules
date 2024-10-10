rule certificate {
    meta:
        description = "detects injection of a certificate into the certificate store"
        version = "0.1"
    strings:
        $f1 = "Cryypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates"
        $c1 = "CertOpenSystemStore"
    condition:
        all of them
}