rule exe
{
    meta:
        description = "Detects an executable file"
    strings:
        $sl = {4D 5A}
    condition:
        $sl at 0
}