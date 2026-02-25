# Threat Actor Profile — Kimsuky (APT43)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** ARCHIPELAGO, Sparkling Pisces, THALLIUM, Velvet Chollima, Emerald Sleet, Springtail, Black Banshee  
**Sponsor:** North Korea — Reconnaissance General Bureau (RGB)  
**First Seen:** 2012  
**Latest Activity:** Active (2026)  
**MITRE ATT&CK:** [G0094](https://attack.mitre.org/groups/G0094/)

---

## Target Countries

Canada, China, Germany, France, United Kingdom, India, Japan, South Korea, Malaysia, Russia, Singapore, Slovakia, Thailand, Ukraine, United States, Vietnam, South Africa

---

## Target Sectors

| Sector | Notes |
|--------|-------|
| National Security & International Affairs | Primary focus |
| Public Administration | Government agencies |
| Space & Defense | Defense contractors, military |
| Educational Services | Universities, research institutes |
| Energy & Utilities | Nuclear, power grid |
| HealthCare & Social Assistance | Hospitals |
| Finance | Banking, cryptocurrency |
| Manufacturing | Industrial targets |
| Information Services | IT, data processing |
| Telecommunications | ISPs, telecom providers |
| Air Transportation | Airlines |
| Computer Systems Design | Technology companies |
| Research & Development | Think tanks, policy research |
| Publishing Services | Media |
| Religious Organizations | Targeted for intelligence |
| Human Rights Organizations | NGOs, activists |

---

## Motivation(s)

- Cyberespionage (political & military intelligence)
- Financial theft (cryptocurrency, ransomware)
- Credential harvesting (spearphishing at scale)
- Nuclear & defense intelligence collection

---

## Toolset

| Tool | Type | Description |
|------|------|-------------|
| BabyShark | Backdoor | VBS-based reconnaissance backdoor |
| AppleSeed | Backdoor | Multi-platform backdoor (Windows/Android) |
| FlowerPower | Stealer | Browser credential stealer |
| GoldDragon | Backdoor | Modular backdoor with keylogging |
| RandomQuery | Recon Tool | System info collection |
| FastViewer | Mobile RAT | Android surveillance |
| ReconShark | Recon Tool | Targeted reconnaissance via Office docs |
| Meterpreter | Post-Exploit | Metasploit framework |
| ChromeLoader | Stealer | Browser extension credential theft |
| TutorialRAT | RAT | PowerShell-based RAT |
| Toddlershark | Backdoor | Polymorphic backdoor |

---

## Modus Operandi

Kimsuky primarily relies on **credential harvesting** and **spearphishing** as initial access vectors:

1. **Credential Phishing**: Fake login pages impersonating Google, Naver, Kakao, and university portals
2. **Spearphishing**: Malicious Office documents (macro-enabled), HWP files targeting Korean users
3. **Social Engineering**: Long-term relationship building with targets via email before delivering payload
4. **Watering Hole**: Compromised websites targeting specific communities
5. **Supply Chain**: Trojanized software updates

Post-compromise operations:
- Browser credential theft and cookie extraction
- Keylogging and screenshot capture
- Email inbox harvesting (IMAP/POP3 credential abuse)
- Lateral movement via RDP, SMB
- Cryptocurrency wallet theft
- Persistent access via scheduled tasks and registry keys

---

## Campaigns Tracked

| Campaign | Period | Description |
|----------|--------|-------------|
| [Apple Phishing](Campaigns/2024_ApplePhishing/) | 2024 | Apple ID phishing targeting Korean users |

---

## References

| Source | URL |
|--------|-----|
| MITRE ATT&CK | [G0094](https://attack.mitre.org/groups/G0094/) |
| CISA Advisory | [AA20-301A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a) |
