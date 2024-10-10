rule sen_data {
    meta:
        description = "Find PII and PII references"
    strings:
        $pii_pattern_1 = /[0-9]{3}-[0-9]{3}-[0-9]{3}/ // SIN
        $pii_pattern_2 = /[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}/ //credit card number
        $phi_pattern_1 = /\b\d{9}\b/ //Alberta Health Care Number
    condition:
        any of ($pii_pattern_1, $pii_pattern_2, $phi_pattern_1)
}