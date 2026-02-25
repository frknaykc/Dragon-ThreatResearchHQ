# DHCSpy — MITRE ATT&CK Mapping (Mobile)

> **Threat Actor:** MuddyWater
> **Malware:** DHCSpy Android Spyware
> **Platform:** Android

---

## Tactic: Resource Development (TA0042)

| Technique | ID | Evidence |
|-----------|----|----------|
| Acquire Infrastructure: Domains | T1583.001 | `earthvpn[.]org`, `comodo-vpn[.]com` registered for distribution |
| Acquire Infrastructure: Server | T1583.004 | SFTP exfil server at `5[.]255[.]118[.]39` |
| Develop Capabilities: Malware | T1587.001 | Custom Android spyware built on modified OpenVPN |

## Tactic: Initial Access (TA0027)

| Technique | ID | Evidence |
|-----------|----|----------|
| Deliver Malicious App via Other Means | T1476 | APK distributed through fake VPN websites (`earthvpn[.]org`) |
| Supply Chain Compromise | T1474 | Trojanized open-source OpenVPN code (`ics-openvpn`) |

## Tactic: Execution (TA0041)

| Technique | ID | Evidence |
|-----------|----|----------|
| Native Code | T1575 | Java-based execution with AIDL IPC to VPN service |

## Tactic: Persistence (TA0028)

| Technique | ID | Evidence |
|-----------|----|----------|
| Boot or Logon Initialization Scripts | T1398 | `RECEIVE_BOOT_COMPLETED` — auto-start after device reboot |
| Foreground Persistence | T1541 | VPN service runs as foreground service (`WAKE_LOCK`, `POST_NOTIFICATIONS`) |

## Tactic: Defense Evasion (TA0030)

| Technique | ID | Evidence |
|-----------|----|----------|
| Masquerade as Legitimate Application | T1655.001 | Disguised as VPN apps (Earth VPN, Comodo VPN, Hide VPN) |
| Abuse Elevation Control Mechanism | T1626 | Xiaomi MIUI autostart bypass via `AndroidHiddenApiBypass` + `Unsafe` API |
| Suppress Application Icon | — | Operates within legitimate VPN UI, no separate icon |

## Tactic: Credential Access (TA0031)

| Technique | ID | Evidence |
|-----------|----|----------|
| Access Stored Application Data | T1409 | WhatsApp encrypted DB theft (`msgstore.db.crypt14`) |

## Tactic: Discovery (TA0032)

| Technique | ID | Evidence |
|-----------|----|----------|
| System Information Discovery | T1426 | Collects device model, OS version, SDK, timezone, language |
| System Network Configuration Discovery | T1422 | Collects network type (WIFI/MOBILE_DATA), public/private IP |
| Software Discovery | T1418 | `getAppList()` — enumerates installed applications |
| System Network Connections Discovery | T1421 | VPN traffic byte counters (inputByteCount/outputByteCount) |

## Tactic: Collection (TA0035)

| Technique | ID | Evidence |
|-----------|----|----------|
| Protected User Data: Contact List | T1636.003 | `getContact()` — reads contacts via READ_CONTACTS |
| Protected User Data: Call Log | T1636.002 | `getCallog()` — reads call log via READ_CALL_LOG |
| Data from Local System | T1533 | Steals files from Downloads, Camera, Screenshots, Recordings |
| Access Stored Application Data | T1409 | WhatsApp DB theft (standard + Business), account data via GET_ACCOUNTS |
| Archive Collected Data | T1532 | Collected data compressed into password-protected ZIP archives |

## Tactic: Command and Control (TA0037)

| Technique | ID | Evidence |
|-----------|----|----------|
| Application Layer Protocol: Web Protocols | T1437.001 | HTTPS POST to `/api/v1` on C2 config servers |
| Encrypted Channel | T1521 | HTTPS for C2 communication |
| Dynamic Resolution | T1637 | Random selection between two C2 URLs at runtime |
| Standard Non-Application Layer Protocol | T1095 | SFTP (SSH-based) for data exfiltration |

## Tactic: Exfiltration (TA0036)

| Technique | ID | Evidence |
|-----------|----|----------|
| Exfiltration Over Alternative Protocol | T1639 | SFTP upload to `5[.]255[.]118[.]39:4793` (not over C2 channel) |
| Data Encrypted | T1532 | ZIP archives with C2-provided 32-character password |

## Tactic: Impact (TA0034)

| Technique | ID | Evidence |
|-----------|----|----------|
| (No destructive impact observed) | — | Espionage-focused, data collection only |

---

## ATT&CK Techniques Summary

**Total unique techniques:** 22

`T1583.001, T1583.004, T1587.001, T1476, T1474, T1575, T1398, T1541, T1655.001, T1626, T1409, T1426, T1422, T1418, T1421, T1636.003, T1636.002, T1533, T1532, T1437.001, T1521, T1637, T1095, T1639`
