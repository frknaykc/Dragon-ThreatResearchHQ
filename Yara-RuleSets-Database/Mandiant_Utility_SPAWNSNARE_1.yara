rule M_Utility_SPAWNSNARE_1 {
    meta:
    	 author = "Mandiant"
        description = "SPAWNSNARE is a utility written in C that targets 
Linux systems by extracting the uncompressed Linux kernel image 
into a file and encrypting it with AES."

    strings:
        $s1 = "\x00extract_vmlinux\x00"
        $s2 = "\x00encrypt_file\x00"
        $s3 = "\x00decrypt_file\x00"
        $s4 = "\x00lbb_main\x00"
        $s5 = "\x00busybox\x00"
        $s6 = "\x00/etc/busybox.conf\x00"

    condition:
        uint32(0) == 0x464c457f
        and all of them
                  
}
