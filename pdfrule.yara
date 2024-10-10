rule PDF {
    meta:
        description = "Detects a PDF file"
    strings:
        $s1 = {25 50 44 46}
    condition:
        $s1 at 0
}
