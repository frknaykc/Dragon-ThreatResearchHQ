rule M_APT_Utility_SPAWNSLOTH_2
{ 
    meta: 
        author = "Mandiant" 
        description = "Hunting rule to identify strings found in SPAWNSLOTH"
  
    strings: 
        $dslog = "dslogserver" ascii fullword
        $hook1 = "g_do_syslog_servers_exist" ascii fullword
        $hook2 = "ZN5DSLog4File3addEPKci" ascii fullword
        $hook3 = "funchook" ascii fullword
    
    condition: 
        uint32(0) == 0x464c457f and all of them
}
