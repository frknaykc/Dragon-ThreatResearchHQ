# MITRE ATT&CK Mapping — DragonFly / Polish Grid Attack (Dec 2025)

> Sources: Truesec, CERT.PL

## Reconnaissance

| Technique | ID | Description |
|-----------|----|-------------|
| Gather Victim Org Info: Business Relationships | T1591.002 | OSINT on organizational relationships |
| Active Scanning: Vulnerability Scanning | T1595.002 | Scanned for vulnerable Citrix and Exchange |
| Phishing for Information: Spearphishing Attachment | T1598.002 | Office docs for credential harvesting |
| Phishing for Information: Spearphishing Link | T1598.003 | PDFs with links to credential harvesting sites |

## Resource Development

| Technique | ID | Description |
|-----------|----|-------------|
| Acquire Infrastructure: Domains | T1583.001 | Registered targeting domains |
| Acquire Infrastructure: VPS | T1583.003 | VPS for C2 operations |
| Compromise Infrastructure: Server | T1584.004 | Compromised legitimate sites for C2/hosting |
| Obtain Capabilities: Tool | T1588.002 | Mimikatz, CrackMapExec, PsExec, Hydra |
| Stage Capabilities: Drive-by Target | T1608.004 | Watering hole exploit kits |

## Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Valid Accounts: Local Accounts | T1078.003 | FortiGate VPN local account login |
| External Remote Services | T1133 | FortiGate VPN, Outlook Web Access |
| Drive-by Compromise | T1189 | Strategic Web Compromise with custom exploit kit |
| Exploit Public-Facing Application | T1190 | CVE-2019-19781 (Citrix), CVE-2020-0688 (Exchange), CVE-2018-13379 (Fortinet) |
| Supply Chain Compromise | T1195.002 | Trojanized ICS vendor software installers |
| Spearphishing Attachment | T1566.001 | Malicious Office attachments |

## Execution

| Technique | ID | Description |
|-----------|----|-------------|
| PowerShell | T1059.001 | Admin share enablement, firewall rules, exfiltration |
| Windows Command Shell | T1059.003 | Batch scripts for enumeration |
| Python | T1059.006 | Python 2.7 installed on victim |
| Scheduled Task | T1053.005 | Wiper distribution via scheduled tasks |
| Service Execution | T1569.002 | PsExec remote execution |
| User Execution: Malicious File | T1204.002 | Spearphishing attachment execution |

## Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Registry Run Keys | T1547.001 | `ntdll` registry value in Run key |
| Valid Accounts | T1078.003 | FortiGate VPN local accounts |
| Create Local Account | T1136.001 | Admin accounts tailored per target |
| Account Manipulation | T1098.007 | Added accounts to administrators group |
| External Remote Services | T1133 | FortiGate VPN persistence |
| Web Shell | T1505.003 | Web shells on Exchange/web servers |
| Scheduled Task | T1053 | FortiGate scripts for credential theft |

## Privilege Escalation

| Technique | ID | Description |
|-----------|----|-------------|
| Access Token Manipulation | T1134 | LSASS credential theft, process token escalation |
| Steal/Forge Kerberos Tickets | T1558 | **Diamond Ticket** creation |

## Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Masquerade Account Name | T1036.010 | Accounts disguised as backup/service accounts |
| Clear Windows Event Logs | T1070.001 | System, security, terminal services, audit logs cleared |
| File Deletion | T1070.004 | Removed tools and screenshots after use |
| Modify Registry | T1112 | Multiple registry modifications via Reg |
| Template Injection | T1221 | SMB URLs injected for forced authentication |
| File Permissions Modification | T1222 | Wiper modifies file permissions before overwrite |
| GPO Modification | T1484.001 | Wiper distributed via "Default Domain Policy" GPO |
| Disable System Firewall | T1562.004 | Host firewalls disabled, port 3389 globally opened |
| Disable Network Firewall | T1562.013 | FortiGate device configuration modified |
| Hidden Users | T1564.002 | Registry modified to hide created accounts |

## Credential Access

| Technique | ID | Description |
|-----------|----|-------------|
| SAM Dump | T1003.002 | SecretsDump for SAM hashes |
| NTDS Dump | T1003.003 | SecretsDump + ntds.dit extraction |
| LSA Secrets | T1003.004 | SecretsDump for LSA secrets |
| Brute Force | T1110 | Hydra, CrackMapExec brute force |
| Password Cracking | T1110.002 | Hydra, CrackMapExec offline cracking |
| Forced Authentication | T1187 | SMB forced auth via spearphishing + LNK icons |
| Diamond Ticket | T1558 | Kerberos Diamond Ticket for persistence |

## Discovery

| Technique | ID | Description |
|-----------|----|-------------|
| Network Configuration Discovery | T1016 | Trust, zone, domain enumeration |
| Remote System Discovery | T1018 | Network system enumeration |
| System Owner/User Discovery | T1033 | `query user` command |
| Network Service Discovery | T1046 | Service enumeration |
| Network Connections Discovery | T1049 | Connection enumeration |
| Process Discovery | T1057 | Running process enumeration |
| File and Directory Discovery | T1083 | File/folder name collection |
| Domain Account Discovery | T1087.002 | Domain user enumeration |
| Network Share Discovery | T1135 | ICS/SCADA file server browsing |
| Local Storage Discovery | T1680 | Wiper disk enumeration |

## Collection

| Technique | ID | Description |
|-----------|----|-------------|
| Data from Local System | T1005 | Local data collection |
| Query Registry | T1012 | Registry data collection |
| Local Data Staging | T1074.001 | Files copied to `%AppData%\out` |
| Screen Capture | T1113 | ScreenUtil (scr.exe) |
| Remote Email Collection | T1114.002 | OWA email access |
| Archive Collected Data | T1560 | ZIP compression before exfiltration |
| Network Device Config Dump | T1602.002 | FortiGate config dump |

## Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| File Transfer Protocols (SMB) | T1071.002 | SMB for C2 |
| Proxy | T1090 | Reverse SOCKS proxy, Tor network |
| Ingress Tool Transfer | T1105 | Tools downloaded from Dropbox |
| Remote Desktop Software | T1219.002 | RDP to internal devices |
| Hide Infrastructure | T1665 | Compromised infrastructure for C2 |

## Exfiltration

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over Web Service | T1567 | HTTP POST via Invoke-RestMethod |
| Exfiltration Over Webhook | T1567.004 | Script results sent to Slack channel |

## Impact

| Technique | ID | Description |
|-----------|----|-------------|
| Data Destruction | T1485 | DynoWiper file corruption on HMI systems |
| Inhibit System Recovery | T1490 | IP addressing changes on compromised devices |
| System Shutdown/Reboot | T1529 | Wiper-initiated device shutdown |
