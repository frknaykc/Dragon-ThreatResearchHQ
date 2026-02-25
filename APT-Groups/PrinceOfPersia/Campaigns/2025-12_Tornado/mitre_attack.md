# MITRE ATT&CK Mapping — Prince of Persia / Tornado v51

> Source: SafeBreach Labs (Part II, Feb 2026)

## Resource Development

| Technique | ID | Description |
|-----------|----|-------------|
| Acquire Infrastructure | T1583 | C2 servers on 45.80.148.x/149.x range, DGA domain registration |
| Develop Capabilities: Malware | T1587.001 | Tornado, Foudre, Tonnerre, ZZ Stealer (custom development) |
| Obtain Capabilities: Tool | T1588.002 | StormKitty (open-source fork), Metasploit, FlashFXP |
| Stage Capabilities | T1608 | Malware hosted on C2 servers and Telegram |

## Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spearphishing Attachment | T1566.001 | Malicious RAR/SFX archives masquerading as documents |
| Exploit Public-Facing Application | T1190 | WinRAR CVE-2025-8088 / CVE-2025-6218 to drop payloads to Startup |

## Execution

| Technique | ID | Description |
|-----------|----|-------------|
| User Execution: Malicious File | T1204.002 | Victim opens tozihat.doc (SFX archive) |
| Command and Scripting: PowerShell | T1059.001 | ZZ Stealer delivered via PowerShell XOR-decoded script |
| Scheduled Task/Job | T1053 | TornadoInstaller creates scheduled task for persistence |
| Shared Modules | T1129 | Tornado main DLL (AuthFWSnapin.dll) loaded by installer |

## Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Boot or Logon Autostart: Startup Folder | T1547.001 | AudioService.exe dropped to Startup via WinRAR exploit |
| Scheduled Task/Job | T1053.005 | Scheduled task created by TornadoInstaller |

## Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Obfuscated Files: Encrypted/Encoded File | T1027.013 | RC4 encrypted StormKitty payload, AES encrypted ZZ Stealer config |
| Masquerading | T1036 | SFX as .doc file, AudioService.exe, chrome.exe |
| Deobfuscate/Decode Files | T1140 | XOR decoding (0x44/0x33), base32 DGA, blockchain deobfuscation |
| Virtualization/Sandbox Evasion | T1497 | Machine name, username, file checks for known sandboxes |
| Indicator Removal: File Deletion | T1070.004 | Communication logs deleted, self-destruct .bat file |
| Domain Generation Algorithms | T1568.002 | Dual DGA: manual (base32+alphabet) and blockchain (OP_RETURN) |

## Credential Access

| Technique | ID | Description |
|-----------|----|-------------|
| Credentials from Web Browsers | T1555.003 | StormKitty/Phantom Stealer browser credential theft |
| Input Capture: Keylogging | T1056.001 | StormKitty keylogger module |

## Discovery

| Technique | ID | Description |
|-----------|----|-------------|
| System Information Discovery | T1082 | Tornado collects sysinfo, GUID, computer name |
| Security Software Discovery | T1518.001 | TornadoInstaller checks for Avast; ZZ Stealer checks for research tools |
| Process Discovery | T1057 | ZZ Stealer monitors for 25+ analysis tool processes |

## Collection

| Technique | ID | Description |
|-----------|----|-------------|
| Screen Capture | T1113 | ZZ Stealer captures screenshots |
| Data from Local System | T1005 | Desktop file collection, browser data |
| Clipboard Data | T1115 | StormKitty clipboard capture |

## Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 with parameters (a=d1/d2/k/s) |
| Web Service: Bidirectional Communication | T1102.002 | Telegram bot API (sendDocument, getUpdates) |
| Dynamic Resolution: DGA | T1568.002 | Manual + blockchain-based domain generation |
| Encrypted Channel | T1573 | RSA signature verification on exfiltrated files |
| Ingress Tool Transfer | T1105 | Tonnerre downloaded by Foudre/Tornado |

## Exfiltration

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over C2 Channel | T1041 | Files exfiltrated via HTTP C2 |
| Exfiltration Over Web Service | T1567 | Files exfiltrated via Telegram bot API (sendDocument) |
