# Threat Actor Profile — Void Arachne (Silver Fox)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** Silver Fox, Void Arachne, Great Thief of the Valley, SwimSnake, UTG-Q-1000  
**Sponsor:** China (suspected state-sponsored / cybercrime hybrid)  
**First Seen:** ~2023  
**Latest Activity:** Active (2026)  

---

## Target Countries

China, Japan, Taiwan, Malaysia, India, South/Southeast Asia

---

## Target Sectors

| Sector | Notes |
|--------|-------|
| Finance | Banking, cryptocurrency, fintech |
| Public Administration | Government agencies |
| Information Services | IT, data processing |
| HealthCare & Social Assistance | Hospitals (Philips DICOM viewers targeted) |
| Software Publishers | Software supply chain |

---

## Motivation(s)

- Cyberespionage (government & financial intelligence)
- Financial theft and fraud
- Healthcare data collection
- Dual espionage/cybercrime operations

---

## Toolset

| Tool | Type | Language | Description |
|------|------|----------|-------------|
| ValleyRAT (Winos 4.0) | RAT | C/C++ | Modular RAT with plugin architecture, kernel-mode rootkit, builder tool |
| VX RAT | RAT | — | Custom RAT variant (win.vx_rat) |
| Meterpreter | Post-Exploit | Multi | Metasploit framework for post-exploitation |
| DeimosC2 | C2 Framework | Go | Open-source C2 framework |
| AsyncRAT | RAT | .NET | Open-source RAT used in some campaigns |
| HoldingHands RAT | RAT | — | Deployed alongside ValleyRAT in Japan/Malaysia campaigns |

### ValleyRAT (Winos 4.0) Capabilities

| Capability | Description |
|-----------|-------------|
| File Management | Upload, download, browse files |
| Screen Capture | Real-time screenshot and recording |
| Webcam Control | Video surveillance |
| Microphone Recording | Audio surveillance |
| Keylogging | Keystroke capture |
| Remote Shell | Interactive command execution |
| DDoS | Distributed denial of service |
| Plugin Architecture | Modular capability expansion |
| Kernel Rootkit | Ring-0 persistence and EDR bypass |
| Privilege Escalation | TrustedInstaller impersonation |

---

## Attack Techniques

### Initial Access
- Spearphishing with malicious PDFs/Excel documents (government impersonation)
- SEO poisoning (fake software download pages)
- Compromised MSI installers distributed via Telegram
- Impersonation of official emails (tax-themed lures in India, Taiwan)
- Fake Philips DICOM viewers targeting healthcare

### Execution & Delivery
- Multi-stage infection chains with RC4 decryption
- DLL sideloading
- Custom shellcode loaders
- NSIS (Nullsoft Installer) abuse
- sRDI (Shellcode Reflective DLL Injection)

### Persistence
- Windows Task Scheduler
- Persistence files: `svchost.ini`, `TimeBrokerClient.dll`, `msvchost.dat`, `system.dat`
- C2 heartbeat: 60-second intervals

### Defense Evasion
- Vulnerable signed driver abuse (BYOVD): `wamsdk.sys`, `amsdk.sys`
- EDR/AV termination via kernel-mode drivers
- Single-byte driver modifications to evade hash-based detection
- Anti-virtualization and anti-antivirus checks
- Dynamic C2 infrastructure rotation

---

## Related CVEs

| CVE | Description |
|-----|-------------|
| CVE-2026-23550 | — |
| CVE-2026-20805 | — |
| CVE-2025-32433 | Erlang/OTP SSH RCE |
| CVE-2025-31324 | SAP NetWeaver unrestricted file upload |
| CVE-2025-29927 | Next.js middleware bypass |

---

## IOCs

| Type | Value | Description |
|------|-------|-------------|
| domain | twsww[.]xin | C2 delivery domain |

> Full IOC list: [iocs.csv](iocs.csv)

---

## Campaigns Tracked

_No dedicated campaign directories yet._

---

## References

| Source | URL |
|--------|-----|
| Trend Micro | [Void Arachne Targets Chinese-Speaking Users](https://www.trendmicro.com/en_us/research/24/f/behind-the-great-wall-void-arachne-targets-chinese-speaking-user.html) |
| Fortinet | [Winos Spreads via Official Email Impersonation (Taiwan)](https://www.fortinet.com/blog/threat-research/winos-spreads-via-impersonation-of-official-email-to-target-users-in-taiwan) |
| Fortinet | [Threat Group Targets Companies in Taiwan](https://www.fortinet.com/blog/threat-research/threat-group-targets-companies-in-taiwan) |
| Check Point | [Cracking ValleyRAT: Builder Secrets to Kernel Rootkits](https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/) |
| Check Point | [Chasing Silver Fox: Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/) |
| Palo Alto Unit 42 | [Espionage Campaign Targets South Asian Entities](https://unit42.paloaltonetworks.com/espionage-campaign-targets-south-asian-entities/) |
| Rapid7 | [NSIS Abuse and sRDI: Winos 4.0 Campaign](https://www.rapid7.com/blog/post/2025/05/22/nsis-abuse-and-srdi-shellcode-anatomy-of-the-winos-4-0-campaign/) |
| CloudSEK | [Silver Fox Targeting India Using Tax-Themed Lures](https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures) |
| Forescout | [Silver Fox APT Targets Philips DICOM Viewers](https://www.forescout.com/blog/healthcare-malware-hunt-part-1-silver-fox-apt-targets-philips-dicom-viewers/) |
| Dark Reading | [Silver Fox APT: Espionage + Cybercrime](https://www.darkreading.com/threat-intelligence/silver-fox-apt-espionage-cybercrime) |
| somedieyoungzz | [Silver Fox Analysis](https://somedieyoungzz.github.io/posts/silver-fox/) |
| ETDA Thailand | [Actor Card](https://apt.etda.or.th/cgi-bin/showcard.cgi?u=f08fc5ff-f408-48bf-a116-e1e98de278b2) |
| Rescana | [Expansion to Japan & Malaysia](https://www.rescana.com/post/silver-fox-expands-winos-4-0-valleyrat-and-holdinghands-rat-cyber-attacks-to-japan-and-malaysia) |
