# DHCSpy — MuddyWater Android Spyware Campaign

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Active-red)
![Platform](https://img.shields.io/badge/Platform-Android-green)

| Field | Value |
|-------|-------|
| **Malware Family** | DHCSpy |
| **Threat Actor** | MuddyWater (MOIS) |
| **Platform** | Android |
| **Language** | Java (modified OpenVPN) |
| **Type** | Spyware / VPN Trojan |
| **First Discovered** | 2023-07-16 (Lookout) |
| **In Development Since** | 2022-08-10 |
| **Latest Sample** | 2025-07-20 (Earth VPN) |
| **Distribution** | Fake VPN websites |
| **Exfiltration** | SFTP with password-protected ZIP |
| **Attribution Confidence** | High |
| **Developer Artifact** | Username `hossein` (compilation traces) |
| **Source** | [Shindan / Randorisec](https://shindan.io/blog/dhcspy-discovering-the-iranian-apt-muddywater) |
| **MITRE ATT&CK** | See [mitre_attack.md](mitre_attack.md) |

## Summary

DHCSpy is a malicious Android spyware family developed and maintained by MuddyWater, disguised as legitimate VPN applications. Built on modified open-source OpenVPN code, it automatically activates whenever the victim uses the VPN. Once running, it silently collects WhatsApp databases, contacts, call logs, camera files, screenshots, recordings, and device information. Data is exfiltrated via SFTP in password-protected ZIP archives. Multiple variants have been identified: **Hide VPN**, **Hazrat Eshq**, **Earth VPN**, and **Comodo VPN**. The malware includes Xiaomi-specific autostart bypass logic, reflecting Iran's device market where Xiaomi ranks second in sales.

## Known Variants

| Variant | Package Name | Version | Distribution Site |
|---------|-------------|---------|-------------------|
| Earth VPN | `com.earth.earth_vpn` | 1.3.0 (versionCode 4) | `www[.]earthvpn[.]org` |
| Comodo VPN | — | — | `comodo-vpn[.]com` |
| Hide VPN | — | — | — (first discovered) |
| Hazrat Eshq | — | — | — |

## Data Theft Capabilities

Controlled via a 16-bit command code sent from C2:

| Bit (from LSB) | Permission | Stolen Data |
|-----------------|-----------|-------------|
| 16 (MSB) | READ_PHONE_STATE | Device info (IMSI, SIM, model) |
| 15 | READ_CONTACTS | Contact list |
| 14 | READ_CALL_LOG | Call history |
| 13 | GET_ACCOUNTS | Accounts on device |
| 12 | — | Installed app list |
| 11 | READ_EXTERNAL_STORAGE | WhatsApp databases (`msgstore.db.crypt14`) |
| 10 | READ_EXTERNAL_STORAGE | Screenshots |
| 9 | READ_EXTERNAL_STORAGE | Camera files |
| 8 | READ_EXTERNAL_STORAGE | Audio recordings |
| 7 | READ_EXTERNAL_STORAGE | Downloads folder |

## C2 Architecture

```
[Victim Android] → HTTPS POST /api/v1 → [C2 Config Server (earthvpn.org:3413)]
                                              ↓
                                    Returns: VPN config + order (command code + SFTP creds)
                                              ↓
[Victim Android] → SFTP upload → [Exfil Server (5.255.118.39:4793)]
                                    (password-protected ZIP archives)
```

## Quick Links

| Resource | File |
|----------|------|
| Detailed Report | [report.md](report.md) |
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| MITRE ATT&CK Mapping | [mitre_attack.md](mitre_attack.md) |

## Changelog

| Date | Change |
|------|--------|
| 2026-02-25 | Structured report created from Shindan/Randorisec analysis |
| 2025-09-29 | Shindan publishes DHCSpy deep-dive |
| 2025-07-20 | Earth VPN sample obtained |
| 2023-07-16 | First discovery by Lookout (Hide VPN) |
| 2022-08-10 | Earliest development traces |
