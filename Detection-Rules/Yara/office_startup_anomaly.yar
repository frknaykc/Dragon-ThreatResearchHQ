/* Requires YARA 3.8 or higher */
import "pe"

rule Office_Startup_Anomaly_NaxoziwuS {
   meta:
      description = "Detects the creation of an uncommon file in Microsoft Office startup folders"
      author = "NaxoziwuS"
      reference = "Custom security research"
      date = "2025-02-11"
      id = "nxz-office-startup-9f3a2b67-4d1f-473d-b9d1-239e4a6f9c81"
      score = 80

   strings:
      // Word Startup Folder Paths
      $word_startup1 = "\\Microsoft\\Word\\STARTUP\\" nocase
      $word_startup2 = "\\Office\\Program Files\\STARTUP\\" nocase

      // Excel Startup Folder Paths
      $excel_startup1 = "\\Microsoft\\Excel\\XLSTART\\" nocase
      $excel_startup2 = "\\Office\\Program Files\\XLSTART\\" nocase

      // Trusted Office File Extensions (Benign)
      $trusted_ext1 = ".docx" ascii
      $trusted_ext2 = ".docm" ascii
      $trusted_ext3 = ".dotm" ascii
      $trusted_ext4 = ".pdf" ascii
      $trusted_ext5 = ".xls" ascii
      $trusted_ext6 = ".xlsx" ascii
      $trusted_ext7 = ".xltm" ascii
      $trusted_ext8 = ".xll" ascii
      $trusted_ext9 = ".wll" ascii
      $trusted_ext10 = ".wwl" ascii

      // Common Malicious File Extensions
      $susp_ext1 = ".exe" ascii
      $susp_ext2 = ".dll" ascii
      $susp_ext3 = ".bat" ascii
      $susp_ext4 = ".js" ascii
      $susp_ext5 = ".vbs" ascii
      $susp_ext6 = ".hta" ascii
      $susp_ext7 = ".ps1" ascii
      $susp_ext8 = ".scr" ascii

   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and
      (
         (any of ($word_startup*) or any of ($excel_startup*)) and
         any of ($susp_ext*) and
         not any of ($trusted_ext*)
      )
}
