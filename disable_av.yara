/*
    Find references to turning off AV
*/


rule no_av {
    meta:
        description = "Contains references to security software"
        version = "0.1"
    strings:
        $s1 = "AWWTray.exe" nocase wide ascii
        $s2 = "Ad-Aware.exe" nocase wide ascii
        $s3 = "MSASCui.exe" nocase wide ascii
        $s4 = "_avp32.exe" nocase wide ascii
        $s5 = "_avpcc.exe" nocase wide ascii
        $s6 = "_avpm.exe" nocase wide ascii
        $s7 = "aAvgApi.exe" nocase wide ascii
        $s8 = "ackwin32.exe" nocase wide ascii
        $s9 = "adaware.exe" nocase wide ascii
        $s10 = "advxdwin.exe" nocase wide ascii
        $s11 = "alertsvc.exe" nocase wide ascii
        $s12 = "alogserv.exe" nocase wide ascii
        $s13 = "amon9x.exe" nocase wide ascii
        $s14 = "alevir.exe" nocase wide ascii
        $s15 = "agentsvr.exe" nocase wide ascii
        $s16 = "agentw.exe" nocase wide ascii
    condition:
        any of them



}