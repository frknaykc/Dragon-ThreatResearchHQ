/* Requires YARA 3.8 or higher */
import "pe"

rule CobaltStrike_Obfuscated_Beacon_NaxoziwuS {
   meta:
      description = "Detects obfuscated Cobalt Strike beacon payloads using XOR, RC4, Base64, and AES encryption"
      author = "NaxoziwuS"
      reference = "Advanced Threat Hunting & Malware Analysis"
      date = "2025-02-11"
      id = "nxz-cobaltstrike-obf-detect-6e3c2b59-5a7d-4d62-bb35-3f9a1e6d7c29"
      score = 99

   strings:
      // 🚨 Base64 & Base85 Obfuscation Patterns (Common in Cobalt Strike Variants)
      $base64_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" ascii
      $base64_urlsafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" ascii
      $base85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~" ascii

      // 🚨 XOR & RC4 Encryption Artifacts
      $xor_key1 = { 80 ?? ?? ?? 30 ?? ?? ?? 75 ?? ?? 88 ?? ?? } // XOR key in memory
      $xor_key2 = { 31 C0 31 DB 31 C9 31 D2 }  // XOR zeroing technique (Cobalt Strike payloads)
      $rc4_key1 = "RC4KeySchedule" ascii wide
      $rc4_key2 = "Encrypted RC4 Payload" ascii wide

      // 🚨 AES & ChaCha20 Encryption Artifacts
      $aes_key1 = "AES-256 CBC" ascii wide
      $aes_key2 = "AES-256 GCM" ascii wide
      $aes_key3 = "AES decryption failure" ascii wide
      $chacha20_key1 = "ChaCha20Poly1305" ascii wide

      // 🚨 Memory Pattern Anomalies (Obfuscated Shellcode)
      $mem1 = "VirtualAlloc" ascii wide
      $mem2 = "WriteProcessMemory" ascii wide
      $mem3 = "NtProtectVirtualMemory" ascii wide
      $mem4 = "UnmapViewOfSection" ascii wide

      // 🚨 API Function Hooking Indicators
      $hook1 = "SetWindowsHookExA" ascii wide
      $hook2 = "SetWindowsHookExW" ascii wide
      $hook3 = "LdrLoadDll" ascii wide
      $hook4 = "NtDelayExecution" ascii wide

      // 🚨 Self-Decryption & Self-Extraction Patterns
      $self_extract1 = "VirtualAllocEx" ascii wide
      $self_extract2 = "RtlDecompressBuffer" ascii wide
      $self_extract3 = "CreateThread" ascii wide

   condition:
      filesize < 15MB and
      (
         (2 of ($base64*) and 2 of ($rc4_key* or $xor_key*)) or
         (2 of ($aes_key*) and 1 of ($chacha20_key*)) or
         (2 of ($mem*) and 2 of ($hook*)) or
         (2 of ($self_extract*) and 2 of ($mem*))
      )
}
