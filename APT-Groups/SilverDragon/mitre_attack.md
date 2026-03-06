# MITRE ATT&CK Mapping — Silver Dragon

> Source: [Check Point Research — March 2026](https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/)  
> Last Updated: 2026-03-03

---

## Resource Development

| Technique | ID | Evidence |
|-----------|----|----------|
| Acquire Infrastructure: Domains | T1583.001 | 13 C2 domains (onedriveconsole[.]com, exchange4study[.]com, etc.) impersonating legitimate services |
| Compromise Infrastructure | T1584 | Cloudflare-protected HTTP C2 servers |

---

## Initial Access

| Technique | ID | Evidence |
|-----------|----|----------|
| Exploit Public-Facing Application | T1190 | Primary initial access — exploitation of internet-facing servers (ToolShell wave overlap) |
| Phishing: Spearphishing Attachment | T1566.001 | Weaponized LNK files targeting Uzbekistan government entities |

---

## Execution

| Technique | ID | Evidence |
|-----------|----|----------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | LNK → cmd.exe → PowerShell extracts byte slices and drops payloads |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Batch scripts (`usFUk.bat`) orchestrate service creation and payload deployment |
| User Execution: Malicious File | T1204.002 | Victim opens LNK attachment triggering payload chain |
| Scheduled Task/Job | T1053 | `exec` command in GearDoor uses scheduled task for execution |
| Native API | T1106 | BamboLoader uses `RtlDecompressBuffer` (LZNT1) for in-memory decompression |

---

## Persistence

| Technique | ID | Evidence |
|-----------|----|----------|
| Create or Modify System Process: Windows Service | T1543.003 | BamboLoader + MonikerLoader registered as hijacked Windows services (wuausrv, bthsrv, COMSysAppSrv, DfSvc, tzsync) |
| Hijack Execution Flow: AppDomain Hijacking | T1574.014 | `dfsvc.exe.config` redirects AppDomain entry point to MonikerLoader; also abuses tzsync |

---

## Privilege Escalation

| Technique | ID | Evidence |
|-----------|----|----------|
| Access Token Manipulation: Token Impersonation | T1134.001 | GearDoor `steal_token <pid>` command; SilverScreen relaunches under active user session via token impersonation |

---

## Defense Evasion

| Technique | ID | Evidence |
|-----------|----|----------|
| Obfuscated Files or Information | T1027 | MonikerLoader: Brainfuck-based string obfuscation; BamboLoader: control flow flattening + junk code |
| Obfuscated Files or Information: Software Packing | T1027.002 | RC4 encryption + LZNT1 compression for Cobalt Strike shellcode |
| Deobfuscate/Decode Files or Information | T1140 | Runtime ADD-XOR decryption (MonikerLoader); RC4+LZNT1 via RtlDecompressBuffer (BamboLoader) |
| Masquerading: Match Legitimate Name or Location | T1036.005 | DLLs/services named after legitimate Windows components (WinSync.dll, Bluetooth Update Service, etc.) |
| System Binary Proxy Execution: Rundll32 / Svchost | T1218 | BamboLoader runs as service DLL under svchost.exe |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | GameHook.exe sideloads BamboLoader (`graphics-hook-filter64.dll`) in phishing chain |
| Reflective Code Loading | T1620 | MonikerLoader reflectively loads second-stage in memory; BamboLoader injects shellcode into child process |
| Indicator Removal on Host: Timestomping | T1070.006 | All archive files share identical creation timestamp (automated framework) |

---

## Credential Access

| Technique | ID | Evidence |
|-----------|----|----------|
| OS Credential Dumping | T1003 | Via Cobalt Strike post-exploitation capabilities |

---

## Discovery

| Technique | ID | Evidence |
|-----------|----|----------|
| System Information Discovery | T1082 | GearDoor heartbeat: hostname, OS version, machine GUID, internal IP |
| Process Discovery | T1057 | GearDoor `ps` command; Cobalt Strike |
| File and Directory Discovery | T1083 | GearDoor `dir` command; heartbeat includes C:\ drive listing |
| Network Configuration Discovery | T1016 | GearDoor `ipconfig` command |
| System Network Connections Discovery | T1049 | GearDoor `netstat` command |

---

## Lateral Movement

| Technique | ID | Evidence |
|-----------|----|----------|
| Remote Services: SSH | T1021.004 | SSHcmd utility for remote execution and file transfer |
| Use Alternate Authentication Material | T1550 | Token impersonation via `steal_token` |
| Lateral Tool Transfer | T1570 | Cobalt Strike SMB beacons for intra-network movement |

---

## Collection

| Technique | ID | Evidence |
|-----------|----|----------|
| Screen Capture | T1113 | SilverScreen — continuous screenshots across all displays with change-detection |
| Data from Local System | T1005 | GearDoor `download` command exfiltrates arbitrary files |
| Archive Collected Data | T1560 | SilverScreen: JPEG+GZIP compressed screenshots; GearDoor: DES-encrypted uploads |

---

## Command and Control

| Technique | ID | Evidence |
|-----------|----|----------|
| Application Layer Protocol: DNS | T1071.004 | Cobalt Strike primary C2 via DNS tunneling (ns1/ns2.onedriveconsole[.]com, ns1.exchange4study[.]com) |
| Application Layer Protocol: Web Protocols | T1071.001 | Cobalt Strike HTTP C2 (Cloudflare-protected); GearDoor via Google Drive HTTPS |
| Web Service: Bidirectional Communication | T1102.002 | GearDoor uses Google Drive as full C2 channel (file-based tasking + exfil) |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | GearDoor: DES encryption; BamboLoader: RC4 |
| Protocol Tunneling | T1572 | Cobalt Strike DNS tunneling; SMB lateral C2 |
| Proxy: External Proxy | T1090.002 | Cobalt Strike C2 behind Cloudflare |

---

## Exfiltration

| Technique | ID | Evidence |
|-----------|----|----------|
| Exfiltration Over C2 Channel | T1041 | GearDoor uploads encrypted files to Google Drive (`.zip` extension) |
| Exfiltration to Cloud Storage | T1567.002 | GearDoor uses Google Drive as exfiltration destination |
