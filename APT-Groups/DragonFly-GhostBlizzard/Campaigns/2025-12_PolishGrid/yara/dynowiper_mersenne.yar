import "pe"

rule possible_wiper_using_mersenne
{
    meta:
        description = "Windows PE < 500 KB containing MT19937 constants and wiper-like imports"
        date = "2026-02-02"
        author = "Nicklas Keijser - Truesec"
        reference = "https://www.truesec.com/hub/blog/detecting-russian-threats-to-critical-energy-infrastructure"
        hash1 = "60c70cdcb1e998bffed2e6e7298e1ab6bb3d90df04e437486c04e77c411cae4b"
        hash2 = "835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5"
        hash3 = "65099f306d27c8bcdd7ba3062c012d2471812ec5e06678096394b238210f0f7c"
        hash4 = "d1389a1ff652f8ca5576f10e9fa2bf8e8398699ddfc87ddd3e26adb201242160"

    strings:
        $const = { 65 89 07 6C }
        $twist = { DF B0 08 99 }
        $mask7f = { FF FF FF 7F }

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "GetLogicalDrives") and
        pe.imports("kernel32.dll", "FindFirstFileW") and
        pe.imports("kernel32.dll", "DeleteFileW") and
        pe.imports("kernel32.dll", "FindNextFileW") and
        pe.imports("kernel32.dll", "SetFileAttributesW") and
        filesize < 500KB and
        ($const and $twist and $mask7f) and
        (
            pe.number_of_signatures == 0 or
            (
                pe.number_of_signatures > 0 and
                not for any i in (0 .. pe.number_of_signatures - 1) :
                (
                    pe.signatures[i].issuer matches /Microsoft/i or
                    pe.signatures[i].subject matches /Microsoft/i
                )
            )
        )
}
