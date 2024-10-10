/*
    Idnetify Issues in Source Code
*/


rule Weak_SSL_TLS_Ciphers_Pattern {
    meta:
        description = "Detects weak SSL/TLS ciphers"
    strings:
        $weakcipher1 = "SSL_RSA_WITH_DES_CBC_SHA" nocase
        $weakcipher2 = "SSLv2" nocase
    condition:
        any of them
}

rule Insecure_Crypto_Pattern {
    meta:
        description = "Detects insecure cryptographic algorithms"
    strings:
        $insecureCrypto1 = "MD5" nocase
        $insecureCrypto2 = "DES" nocase
    condition:
        any of them
}

rule Unvalidated_Input_Pattern {
    meta:
        description = "Detects unvalidated input"
    strings:
        $unvalidatedInput1 = "gets(" 
        $unvalidatedInput2 = "scanf(" nocase
    condition:
        any of them
}
