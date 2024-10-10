rule SMTP_command {
    meta:
        description = "Detects SMTP commands"
        version = "0.1"
    strings:
        $s1 = "HELO" 
        $s2 = "EHLO"
        $s3 = "MAIL FROM:"
        $s4 = "RCPT TO:"
    condition:
        any of them

}