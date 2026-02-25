# MITRE ATT&CK Mapping — MuddyViper / Fooder Campaign

> ATT&CK v17 | Source: ESET Research

## Reconnaissance

| Technique | ID | Description |
|-----------|----|-------------|
| Gather Victim Org Information | T1591 | Gathers victim org info for spearphishing emails |

## Resource Development

| Technique | ID | Description |
|-----------|----|-------------|
| Acquire Infrastructure | T1583 | Hosts malware and C2 servers |
| Stage Capabilities | T1608 | Stages tools on OneHub, Mega |
| Develop Capabilities: Malware | T1587.001 | MuddyViper, Fooder, LP-Notes, CE-Notes, Blub |
| Obtain Capabilities: Tool | T1588.002 | HackBrowserData, go-socks5 from GitHub |

## Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spearphishing Link | T1566.002 | PDF with links to OneHub/Mega hosting RMM installers |

## Execution

| Technique | ID | Description |
|-----------|----|-------------|
| PowerShell | T1059.001 | MuddyViper executes PowerShell |
| Windows Command Shell | T1059.003 | MuddyViper reverse shell via cmd.exe |
| COM: ITaskService | T1559.001 | MuddyViper creates scheduled tasks via COM |
| Native API | T1106 | CreateProcess for execution |
| User Execution: Malicious Link | T1204.001 | Victims click phishing links |

## Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Registry Run Keys / Startup Folder | T1547.001 | MuddyViper copies to Startup folder |
| Windows Service | T1543.003 | RMM tools install as autostart services |
| Scheduled Task | T1053 | `ManageOnDriveUpdater` task |

## Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Token Impersonation | T1134.001 | LP-Notes/CE-Notes impersonate user context |
| Deobfuscate Files | T1140 | AES decryption of embedded payloads |
| Reflective Code Loading | T1620 | Fooder reflectively loads MuddyViper in memory |
| Time Based Evasion | T1497.003 | Snake game loop delays + Sleep API calls |
| Dynamic API Resolution | T1027.007 | CE-Notes/LP-Notes runtime string decryption |
| Create Process with Token | T1134.002 | Fooder launcher duplicates token via CreateProcessAsUserA |
| Debugger Evasion | T1622 | MuddyViper detects debugging tools |
| Clear Persistence | T1070.009 | MuddyViper clears registry on uninstall |
| File Deletion | T1070.004 | MuddyViper self-deletes |
| Masquerading | T1036 | Fooder poses as Snake game |
| Masquerade Task | T1036.004 | `ManageOnDriveUpdater` task name |
| Modify Registry | T1112 | Startup folder registry manipulation |
| Embedded Payloads | T1027.009 | AES-encrypted payload inside Fooder |
| Encrypted/Encoded File | T1027.013 | AES-encrypted payload inside Fooder |

## Credential Access

| Technique | ID | Description |
|-----------|----|-------------|
| Credentials from Web Browsers | T1555.003 | CE-Notes, Blub steal browser credentials |
| GUI Input Capture | T1056.002 | Fake Windows Security dialog (MuddyViper cmd 805, LP-Notes) |

## Discovery

| Technique | ID | Description |
|-----------|----|-------------|
| System Information Discovery | T1082 | MuddyViper collects system info |
| Security Software Discovery | T1518.001 | MuddyViper checks 150+ security processes |

## Collection

| Technique | ID | Description |
|-----------|----|-------------|
| Local Data Staging | T1074.001 | Blub/CE-Notes/LP-Notes stage data on disk |
| Archive via Utility | T1560.001 | PowerShell Compress-Archive for browser data |

## Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Symmetric Cryptography | T1573.001 | AES-CBC encryption for C2 |
| Remote Access Software | T1219 | Atera, Level, PDQ, SimpleHelp RMM tools |
| Web Protocols | T1071.001 | HTTPS for C2 communications |
| Ingress Tool Transfer | T1105 | Download payloads from C2 |
| Data Obfuscation | T1001 | Command ID hidden in HTTP Status header |
| Proxy | T1090 | go-socks5 reverse proxy tunnels |

## Exfiltration

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over C2 Channel | T1041 | Data exfiltrated via HTTP/HTTPS C2 |
| Data Transfer Size Limits | T1030 | Chunked file upload/download |
