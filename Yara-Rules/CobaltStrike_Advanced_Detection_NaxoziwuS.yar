/* Requires YARA 3.8 or higher */
import "pe"

rule CobaltStrike_Advanced_Detection_NaxoziwuS {
   meta:
      description = "Advanced detection of Cobalt Strike beacons in-memory and on-disk"
      author = "NaxoziwuS"
      reference = "Advanced Threat Hunting & Malware Analysis"
      date = "2025-02-11"
      id = "nxz-cobaltstrike-adv-detect-9a3f1d72-4b9c-4c62-baa2-7d2e9a5b7d39"
      score = 95

   strings:
      // Cobalt Strike Common Signatures
      $cobalt1 = "Malleable C2 Profile" ascii wide
      $cobalt2 = "ReflectiveLoader" ascii wide
      $cobalt3 = "Cobalt Strike" ascii wide
      $cobalt4 = "SMB Beacon" ascii wide
      $cobalt5 = "https://www.cobaltstrike.com/help-beacon" ascii wide

      // Obfuscated & Encrypted Patterns (Commonly Used in Variants)
      $enc1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" ascii
      $enc2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" ascii
      $enc3 = "RC4 encrypted payload" ascii
      $enc4 = "XOR encrypted shellcode" ascii
      $enc5 = "AES256 CBC" ascii wide
      $enc6 = "Obfuscation Key" ascii wide

      // Process Injection and Hollowing Techniques
      $inj1 = "VirtualAllocEx" ascii wide
      $inj2 = "WriteProcessMemory" ascii wide
      $inj3 = "SetThreadContext" ascii wide
      $inj4 = "CreateRemoteThread" ascii wide
      $inj5 = "NtUnmapViewOfSection" ascii wide
      $inj6 = "ResumeThread" ascii wide
      $inj7 = "NtQueueApcThread" ascii wide
      $inj8 = "ZwSuspendThread" ascii wide

      // Suspicious Network Artifacts
      $net1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
      $net2 = "Accept-Encoding: gzip, deflate" ascii
      $net3 = "application/x-www-form-urlencoded" ascii

      // Malicious DLL Indicators
      $dll1 = ".text" ascii
      $dll2 = ".data" ascii
      $dll3 = ".rdata" ascii
      $dll4 = "ReflectiveDLL" ascii wide
      $dll5 = "ReflectiveLoader" ascii wide

   condition:
      filesize < 20MB and
      (
         (3 of ($cobalt*) and 2 of ($enc*)) or
         (3 of ($inj*) and 2 of ($dll*)) or
         (2 of ($net*) and 2 of ($enc*))
      )
}
