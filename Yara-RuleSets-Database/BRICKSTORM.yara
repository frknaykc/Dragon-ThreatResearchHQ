rule NVISO_BACKDOOR_BRICKSTORM {
 meta:
    description = "Detects the BRICKSTORM backdoor Windows executables"
    author = "NVISO"
    created = "2024-11-25"
    md5 = "8af1c3f39b60072d4b68c77001d58109"
    md5 = "c65d7f8accb57a95e3ea8a07fac9550f"
    license = "Detection Rule License (DRL) 1.1"
    reference = "https://nviso.eu/blog/nviso-analyzes-brickstorm-espionage-backdoor"
 strings:
    $lib1 = "wsshell/core/task.DoTask" ascii wide
    $lib2 = "wssoft/core/task.DoTask" ascii wide
    $wss = "wss://" ascii wide
    $go = "/golang.org/" ascii wide
    $doh01 = "https://1.0.0.1/dns-query" ascii wide
    $doh02 = "https://1.1.1.1/dns-query" ascii wide
    $doh03 = "https://8.8.4.4/dns-query" ascii wide
    $doh04 = "https://8.8.8.8/dns-query" ascii wide
    $doh05 = "https://9.9.9.9/dns-query" ascii wide
    $doh06 = "https://9.9.9.11/dns-query" ascii wide
    $doh07 = "https://45.90.28.160/dns-query" ascii wide
    $doh08 = "https://45.90.30.160/dns-query" ascii wide
    $doh09 = "https://149.112.112.11/dns-query" ascii wide
    $doh10 = "https://149.112.112.112/dns-query" ascii wide
    $cmd1 = "/get-file" ascii wide
    $cmd2 = "/put-file" ascii wide
    $cmd3 = "/slice-up" ascii wide
    $cmd4 = "/file-md5" ascii wide
 condition:
    uint16be(0) == 0x4D5A
    and any of ($lib*)
    and any of ($doh*)
    and any of ($cmd*)
    and $wss and $go
}
