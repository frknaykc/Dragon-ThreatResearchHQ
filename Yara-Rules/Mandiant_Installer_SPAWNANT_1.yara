rule M_APT_Installer_SPAWNANT_1
{ 
    meta: 
        author = "Mandiant" 
        description = "Detects SPAWNANT. SPAWNANT is an 
Installer targeting Ivanti devices. Its purpose is to persistently 
install other malware from the SPAWN family (SPAWNSNAIL, 
SPAWNMOLE) as well as drop additional webshells on the box." 
  
    strings: 
        $s1 = "dspkginstall" ascii fullword
        $s2 = "vsnprintf" ascii fullword
        $s3 = "bom_files" ascii fullword
        $s4 = "do-install" ascii
        $s5 = "ld.so.preload" ascii
        $s6 = "LD_PRELOAD" ascii
        $s7 = "scanner.py" ascii
        
    condition: 
        uint32(0) == 0x464c457f and 5 of ($s*)
}
