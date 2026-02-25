# MITRE ATT&CK Mapping — Ghost Tap NFC Payment Relay

> Source: Group-IB (2026)

## Resource Development

| Technique | ID | Description |
|-----------|----|-------------|
| Acquire Infrastructure: Domains | T1583.001 | C2 server infrastructure for WebSocket relay |
| Obtain Capabilities: Malware | T1588.001 | Ghost Tap APKs (TX-NFC, X-NFC, NFU Pay) |
| Obtain Capabilities: Tool | T1588.002 | NFCProxy open-source base, 360 Jiagu packer |
| Stage Capabilities: Upload Malware | T1608.001 | APKs distributed via direct download links and Telegram |

## Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spearphishing via Service | T1566.003 | Smishing (SMS phishing) to deliver malicious APK links |
| Phishing: Spearphishing Voice | T1566.004 | Vishing (voice phishing) to trick victims into installing APKs |

## Execution

| Technique | ID | Description |
|-----------|----|-------------|
| User Execution: Malicious File | T1204.002 | Victim installs malicious APK disguised as banking app |

## Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Event Triggered Execution | T1546 | Foreground service permission ensures app runs continuously |

## Collection

| Technique | ID | Description |
|-----------|----|-------------|
| Input Capture | T1056 | NFC card data capture via Reader app |
| Data from Local System | T1005 | Payment card AIDs and NFC data collected |
| Automated Collection | T1119 | Automatic NFC data capture when card contacts phone |

## Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | WebSocket C2 for real-time NFC data relay |
| Encrypted Channel | T1573 | WebSocket over TLS for C2 communication |
| Remote Access Software | T1219 | Real-time remote control of payment relay |

## Exfiltration

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over C2 Channel | T1041 | NFC payment data relayed through WebSocket C2 |
| Automated Exfiltration | T1020 | Captured NFC data immediately transmitted to C2 |

## Impact

| Technique | ID | Description |
|-----------|----|-------------|
| Financial Theft | T1657 | Unauthorized tap-to-pay transactions ($355K+ single vendor) |

## Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Obfuscated Files or Information: Software Packing | T1027.002 | 360 Jiagu commercial packer for APK obfuscation |
| Masquerading | T1036 | APKs disguised as legitimate banking applications |
| Impair Defenses | T1562 | Foreground service to prevent OS from killing app |
