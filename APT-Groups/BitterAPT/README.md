# A suspicious cyber espionage group of South Asian origin, known as **Bitter**, targeted an institution in the defense sector in November 2024. In this attack, two C++-based malware, **WmRAT** and **MiyaRAT**, were used to gain remote access to systems and steal data.

### You can find the IOC file for Bitter APT 2024 in the following link: [Bitter2024-IOC.csv](https://github.com/frknaykc/Database-Dragon/blob/main/IOCs-Database/BitterAPT/2024/Bitter2024-IOC.csv)


### Attack Methods

1. **Fake PDF Files**:
   - The group used fake PDF files related to World Bank public projects as bait.
   - These fake documents were designed to look trustworthy and deceive the target.

2. **NTFS Alternate Data Streams (ADS)**:
   - Malicious PowerShell scripts were hidden inside seemingly harmless files using the Alternate Data Streams (ADS) of the NTFS file system in Windows.
   - This technique allowed the malicious payload to be stored without altering the file’s size or appearance.

3. **RAR Archive and Shortcut (LNK) Files**:
   - The RAR archive sent to the target contained a hidden ADS file with a Windows shortcut (LNK) file and a malicious PowerShell script.
   - When the user launched the LNK file, a Base64-encoded PowerShell script was executed. This script:
     1. Downloads a bait document from the official World Bank website.
     2. Creates a scheduled task on the target system to download malicious payloads from a malicious domain like **jacknwoods[.]com**.

### Malwares Used

**WmRAT** and **MiyaRAT**:
- Both malware have standard Remote Access Trojan (RAT) capabilities. These include:
  - File upload/download
  - Screenshot capture
  - Collecting system and network information
  - Listing files and directories
  - Command execution (via **cmd.exe** or PowerShell)
  - Collecting geolocation data
- **MiyaRAT** is selectively used and typically preferred for high-value targets.

### Bitter APT Group and History

- The **Bitter** group, tracked under the name **TA397**, is also known by **APT-C-08**, **APT-Q-37**, **Hazy Tiger**, and **Orange Yali**.
- The group has been actively conducting cyber espionage activities since at least 2013.
- In previous operations, countries such as China, Pakistan, India, Saudi Arabia, and Bangladesh were targeted with **BitterRAT**, **ArtraDownloader**, and **ZxxZ** malware.
- In 2019 and 2022, it was also associated with **PWNDROID2** and **Dracarys** malware targeting Android devices.

### Recent Attacks

- In March 2024, the **Bitter** group used a Trojan with data theft and remote control capabilities to target a Chinese government institution.
- Most recently, this attack targeted the defense sector, using bait related to infrastructure projects in Madagascar.
- The techniques used in this attack were carefully designed to covertly deploy malicious software and maintain long-term access to the systems.



