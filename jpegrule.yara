rule JPEG {
    meta:
        Description = "Detects a JPEG file"
    strings:
        $s1 = {FF D8}
    condition:
        $s1 at 0
}
