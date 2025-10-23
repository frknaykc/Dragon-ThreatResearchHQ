/* requires YARA 3.8 or higher */
import "pe"

rule XOR_Hunter_NaxoziwuS {
   meta:
      description = "Detects XOR encoded URLs in an executable (Customized for NaxoziwuS)"
      author = "NaxoziwuS"
      reference = "Custom security research"
      date = "2025-02-11"
      score = 70
      id = "nxz-xor-hunter-7d5b3e29-4f1a-4cbd-bcd6-89e3a4f7c9d8"

   strings:
      // XOR encoded URLs
      $xor_url1 = "http://" xor
      $xor_url2 = "https://" xor
      $xor_domain1 = ".com" xor
      $xor_domain2 = ".net" xor
      $xor_domain3 = ".org" xor
      $xor_domain4 = ".xyz" xor
      $xor_domain5 = ".ru" xor
      $xor_domain6 = ".onion" xor

      // Plain ASCII URLs
      $plain_http = "http://" ascii
      $plain_https = "https://" ascii

      // Common security tools, software, and trusted sources (False Positive Prevention)
      $trusted1 = "Microsoft Corporation" wide fullword
      $trusted2 = "Kaspersky Lab" wide fullword
      $trusted3 = "ESET, spol. s r.o." wide fullword
      $trusted4 = "McAfee, LLC" wide fullword
      $trusted5 = "Symantec Corporation" wide fullword
      $trusted6 = "Google LLC" wide fullword
      $trusted7 = "Mozilla Foundation" wide fullword
      $trusted8 = "Windows Defender" wide fullword
      $trusted9 = "VirusTotal" wide fullword
      $trusted10 = "DigiCert Inc" wide fullword
      $trusted11 = "Let’s Encrypt" wide fullword
      $trusted12 = "Intel Corporation" wide fullword
      $trusted13 = "AMD, Inc." wide fullword
      $trusted14 = "Qualcomm Technologies, Inc." wide fullword
      $trusted15 = "Broadcom Inc." wide fullword
      $trusted16 = "IBM Corporation" wide fullword
      $trusted17 = "Cisco Systems, Inc." wide fullword
      $trusted18 = "NVIDIA Corporation" wide fullword
      $trusted19 = "Oracle Corporation" wide fullword
      $trusted20 = "Red Hat, Inc." wide fullword
      $trusted21 = "Canonical Ltd." wide fullword
      $trusted22 = "SUSE LLC" wide fullword
      $trusted23 = "Palo Alto Networks" wide fullword
      $trusted24 = "Fortinet, Inc." wide fullword
      $trusted25 = "Check Point Software Technologies" wide fullword
      $trusted26 = "CrowdStrike, Inc." wide fullword
      $trusted27 = "FireEye, Inc." wide fullword
      $trusted28 = "Trend Micro, Inc." wide fullword
      $trusted29 = "F-Secure Corporation" wide fullword
      $trusted30 = "Sophos Ltd." wide fullword
      $trusted31 = "Bitdefender SRL" wide fullword
      $trusted32 = "Malwarebytes Inc." wide fullword
      $trusted33 = "NortonLifeLock Inc." wide fullword
      $trusted34 = "Comodo Group, Inc." wide fullword
      $trusted35 = "Cloudflare, Inc." wide fullword
      $trusted36 = "Akamai Technologies, Inc." wide fullword
      $trusted37 = "VeriSign, Inc." wide fullword
      $trusted38 = "McAfee Enterprise" wide fullword
      $trusted39 = "Cisco Talos" wide fullword
      $trusted40 = "Netcraft Ltd." wide fullword
      $trusted41 = "Armis Security" wide fullword
      $trusted42 = "Tenable, Inc." wide fullword
      $trusted43 = "Qualys, Inc." wide fullword
      $trusted44 = "Rapid7 LLC" wide fullword
      $trusted45 = "BlackBerry Cybersecurity" wide fullword
      $trusted46 = "Darktrace Ltd." wide fullword
      $trusted47 = "SentinelOne, Inc." wide fullword
      $trusted48 = "Cylance Inc." wide fullword
      $trusted49 = "Zscaler, Inc." wide fullword
      $trusted50 = "Splunk, Inc." wide fullword

   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and (
         ( $xor_url1 and #xor_url1 > #plain_http ) or
         ( $xor_url2 and #xor_url2 > #plain_https ) or
         ( $xor_domain1 and #xor_domain1 > 0 ) or
         ( $xor_domain2 and #xor_domain2 > 0 ) or
         ( $xor_domain3 and #xor_domain3 > 0 ) or
         ( $xor_domain4 and #xor_domain4 > 0 ) or
         ( $xor_domain5 and #xor_domain5 > 0 ) or
         ( $xor_domain6 and #xor_domain6 > 0 )
      )
      and not for any i in (0..49): (trusted[i] wide fullword in (pe.imphash))
      and not pe.number_of_signatures > 0
}
