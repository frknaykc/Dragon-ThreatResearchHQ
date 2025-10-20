rule M_Hunting_Backdoor_BRICKSTORM_1 {
  meta:
    author = "Mandiant"
    created = "2024-01-30"
    md5 = "4645f2f6800bc654d5fa812237896b00"
    descr = "Hunting rule looking for BRICKSTORM golang backdoor samples"
  strings:
    $v1 = "/home/vsphere-ui/vcli" ascii wide
    $v2 = "/opt/vmware/sbin" ascii wide
    $v3 = "/opt/vmware/sbin/vami-httpd" ascii wide
    $s1 = "github.com/gorilla/mux" ascii wide
    $s2 = "WRITE_LOG=true" ascii wide
    $s3 = "wssoft" ascii wide
    
  condition:
    uint32(0) == 0x464c457f and filesize < 6MB and 1 of ($v*) and 2 of ($s*)
}
