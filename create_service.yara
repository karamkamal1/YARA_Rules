rule create_service {
    meta:
        description = "detects the creation of a windows service"
        version = "0.1"
    strings:
        $f1 = "Advapi32.dll" nocase
        $c1 = "CreateService"
        $c2 = "ControlService"
        $c3 = "StartService"
        $c4 = "QueryServiceStatus"
    condition:
        $f1 and 1 of ($c*)
}
