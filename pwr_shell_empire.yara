rule ps_empire {
    meta:
        description = "Find references to Empire PowerShell and Empire Powershell Commands"
        version = "0.1"
    strings:
        $c1 = "Invoke-Empire"
        $s1 = "powershell-empire"
        $s2 = "EmpireAgent"
    
    condition:
        any of them

}