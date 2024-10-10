/*
    Files and commands related to audio sniffings
*/

rule sniff_audio{
    meta:
        description = "Detects Commands related to audio sniffing"
        version = "0.1"
    strings:
        $f1 = "Winmm.dll" nocase
        $c1 = "waveInStart"
        $c2 = "waveInReset"
        $c3 = "WaveInAddBuffer"
        $c4 = "waveInOpen"
        $c5 = "waveInClose"
    condition:
        $f1 and 2 of ($c*)
}