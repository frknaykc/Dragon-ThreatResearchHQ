# Operation Olalampo — MITRE ATT&CK Mapping

> **Threat Actor:** MuddyWater  
> **Campaign:** Operation Olalampo (Jan–Feb 2026)

---

## Tactic: Reconnaissance (TA0043)

| Technique | ID | Evidence |
|-----------|----|----------|
| Gather Victim Org Information | T1591 | Phishing documents themed around specific energy/marine company |

## Tactic: Resource Development (TA0042)

| Technique | ID | Evidence |
|-----------|----|----------|
| Acquire Infrastructure: Domains | T1583.001 | `promoverse[.]org`, `codefusiontech[.]org`, `miniquest[.]org` registered via NameCheap |
| Acquire Infrastructure: Server | T1583.004 | VPS infrastructure at 209.74.87.x range |
| Develop Capabilities: Malware | T1587.001 | CHAR, GhostFetch, GhostBackDoor, HTTP_VIP — all custom-developed |
| Obtain Capabilities: Tool | T1588.002 | AnyDesk RMM tool, FMAPP.exe (legitimate for sideloading) |
| Stage Capabilities: Upload Malware | T1608.001 | Open directory on 209.74.87.100 with tools |
| Establish Accounts: Social Media | T1585.001 | Telegram bot `stager_51_bot` created for C2 |

## Tactic: Initial Access (TA0001)

| Technique | ID | Evidence |
|-----------|----|----------|
| Phishing: Spearphishing Attachment | T1566.001 | Malicious Office documents (Excel/Word) with macro payloads |
| Exploit Public-Facing Application | T1190 | Active exploitation of recently disclosed vulnerabilities |

## Tactic: Execution (TA0002)

| Technique | ID | Evidence |
|-----------|----|----------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell commands via Telegram bot for tool deployment and exfiltration |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd` execution via GhostBackDoor and CHAR |
| User Execution: Malicious File | T1204.002 | Victim must enable macros in Office documents |
| Scheduled Task/Job: Scheduled Task | T1053.005 | `schtasks /create /sc daily /st 09:00 /tn "DailyUpdate" /tr novaservice.exe` |

## Tactic: Persistence (TA0003)

| Technique | ID | Evidence |
|-----------|----|----------|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | GhostFetch: `User Shell Folders\Startup` registry persistence |
| Create or Modify System Process: Windows Service | T1543.003 | GhostBackDoor installs as `MicrosoftVersionUpdater` service (admin) |
| Scheduled Task/Job: Scheduled Task | T1053.005 | `DailyUpdate` scheduled task for `novaservice.exe` |

## Tactic: Privilege Escalation (TA0004)

| Technique | ID | Evidence |
|-----------|----|----------|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Same as persistence |
| Create or Modify System Process: Windows Service | T1543.003 | Same as persistence |

## Tactic: Defense Evasion (TA0005)

| Technique | ID | Evidence |
|-----------|----|----------|
| Obfuscated Files or Information: Encoding | T1027.013 | Decimal-encoded payloads in `UserForm1.TextBox1.Text`; Base64-encoded PowerShell |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | GhostFetch checks RAM, CPU, USB count, screen resolution, mouse movement |
| Virtualization/Sandbox Evasion: Time-Based | T1497.003 | `GetTickCount64` timing checks; nested-loop sleep evasion in macros |
| Indicator Removal: File Hash Modification | T1070.003 | GhostFetch modifies its own binary on copy to change hash; AnyDesk random byte appending |
| Masquerading: Match Legitimate Name | T1036.005 | `MicrosoftExcelUser.exe`, `MicrosoftWordUser.exe`, `MicrosoftVersionUpdater` service |
| Masquerading: Masquerade File Type | T1036.008 | `pic.LOG` extension for executable payload |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | `FMAPP.exe` legitimate binary sideloads `FMAPP.dll` |
| Hide Artifacts: Hidden Window | T1564.003 | `-WindowStyle Hidden` on all PowerShell executions |
| Reflective Code Loading | T1620 | GhostFetch reflectively loads AES-decrypted PE into memory |

## Tactic: Credential Access (TA0006)

| Technique | ID | Evidence |
|-----------|----|----------|
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | `cobe-notes.txt` — MuddyWater's custom browser infostealer output |

## Tactic: Discovery (TA0007)

| Technique | ID | Evidence |
|-----------|----|----------|
| System Owner/User Discovery | T1033 | `whoami`, `whoami /all` |
| System Network Configuration Discovery | T1016 | `ipconfig /all`, `nslookup ad` |
| Domain Trust Discovery | T1482 | `nslookup ad` for AD discovery |
| Permission Groups Discovery: Domain Groups | T1069.002 | `net group "domain admins" /do` |
| Account Discovery: Domain Account | T1087.002 | `net user /do` |
| File and Directory Discovery | T1083 | `dir`, `dir ..\desktop`, `dir c:\users\public\downloads` |
| Remote System Discovery | T1018 | `ping -n 2 -a <target>` for network scanning |
| System Information Discovery | T1082 | HTTP_VIP collects hostname, Windows version, build, AV name |
| Software Discovery: Security Software | T1518.001 | HTTP_VIP reports `X-Antivirus-Name` header |
| Process Discovery | T1057 | `taskkill /IM novaservice.exe` implies process awareness |

## Tactic: Lateral Movement (TA0008)

| Technique | ID | Evidence |
|-----------|----|----------|
| Remote Services | T1021 | AnyDesk RMM deployment for direct remote access |

## Tactic: Collection (TA0009)

| Technique | ID | Evidence |
|-----------|----|----------|
| Data from Local System | T1005 | File read commands via GhostBackDoor |
| Clipboard Data | T1115 | HTTP_VIP new variant: command 210 captures clipboard |
| Archive Collected Data | T1560 | Credential data collected in `cobe-notes.txt` |

## Tactic: Command and Control (TA0011)

| Technique | ID | Evidence |
|-----------|----|----------|
| Application Layer Protocol: Web Protocols | T1071.001 | GhostBackDoor and HTTP_VIP use HTTPS for C2 |
| Web Service: Bidirectional Communication | T1102.002 | CHAR uses Telegram Bot API for C2 |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | GhostBackDoor: AES-encrypted C2 communications |
| Proxy: External Proxy | T1090.002 | Apache reverse proxy fronting Flask C2 backend |
| Ingress Tool Transfer | T1105 | Downloads of FMAPP, sh.exe, gshdoc, dllapp.dll, AnyDesk via C2 |
| Data Encoding: Standard Encoding | T1132.001 | Decimal and Base64 encoding in payloads and commands |
| Non-Standard Port | T1571 | C2 on port 8080 internally, exfil on 143.198.5.41:443 |
| Protocol Tunneling | T1572 | FMAPP.dll SOCKS5 reverse proxy for traffic tunneling |

## Tactic: Exfiltration (TA0010)

| Technique | ID | Evidence |
|-----------|----|----------|
| Exfiltration Over C2 Channel | T1041 | Credential file upload via WebClient to `143[.]198[.]5[.]41:443/success` |
| Exfiltration Over Alternative Protocol | T1048 | `cobe-notes.txt` uploaded to separate exfiltration server |

## Tactic: Impact (TA0040)

| Technique | ID | Evidence |
|-----------|----|----------|
| (No direct impact techniques observed) | — | Campaign focused on espionage and data collection |

---

## ATT&CK Navigator Layer

**Techniques covered:** T1591, T1583.001, T1583.004, T1587.001, T1588.002, T1608.001, T1585.001, T1566.001, T1190, T1059.001, T1059.003, T1204.002, T1053.005, T1547.001, T1543.003, T1497.001, T1497.003, T1027.013, T1070.003, T1036.005, T1036.008, T1574.002, T1564.003, T1620, T1555.003, T1033, T1016, T1482, T1069.002, T1087.002, T1083, T1018, T1082, T1518.001, T1057, T1021, T1005, T1115, T1560, T1071.001, T1102.002, T1573.001, T1090.002, T1105, T1132.001, T1571, T1572, T1041, T1048

**Total unique techniques:** 46
