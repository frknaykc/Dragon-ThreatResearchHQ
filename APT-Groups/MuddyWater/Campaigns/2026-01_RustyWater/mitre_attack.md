# MITRE ATT&CK Mapping — RustyWater Campaign

> Source: CloudSEK / Seqrite Labs / The Hacker News

## Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spearphishing Attachment | T1566.001 | Word documents with VBA macros posing as cybersecurity guidelines |

## Execution

| Technique | ID | Description |
|-----------|----|-------------|
| User Execution: Malicious File | T1204.002 | Victim enables content to trigger VBA macro |
| Command and Scripting Interpreter: VBA | T1059.005 | VBA macro deploys Rust binary |

## Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Registry key for persistence |

## Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Obfuscated Files or Information | T1027 | Rust binary with anti-analysis |
| Virtualization/Sandbox Evasion | T1497 | Anti-analysis capabilities |

## Discovery

| Technique | ID | Description |
|-----------|----|-------------|
| System Information Discovery | T1082 | Collects victim machine info |
| Security Software Discovery | T1518.001 | Detects installed security software |

## Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | Async C2 via nomercys.it[.]com |
| Ingress Tool Transfer | T1105 | Download additional payloads |

## Exfiltration

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over C2 Channel | T1041 | Data exfiltrated via C2 |
