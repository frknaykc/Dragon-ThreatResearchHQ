# Threat Actor Profile — Dropping Elephant (Patchwork)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** Patchwork, TG-4410, Zinc Emerson, G0040, Monsoon, Capricorn Organisation, Thirsty Gemini, APT-C-09, Chinastrats, Maha Grass, ATK 11, Operation HangOver, Viceroy Tiger, G0042, Neon, Quilted Tiger  
**Sponsor:** India (suspected state-sponsored)  
**First Seen:** 2009 (Operation HangOver)  
**Latest Activity:** Active (2025)  
**MITRE ATT&CK:** [G0040](https://attack.mitre.org/groups/G0040/)

---

## Target Countries

Austria, Bangladesh, Bhutan, Canada, China, Germany, France, Indonesia, Israel, India, Iran, Jordan, Japan, Cambodia, South Korea, Kuwait, Sri Lanka, Myanmar, Norway, Nepal, Oman, Panama, Pakistan, Poland, Romania, Singapore, Thailand, Turkey, Taiwan, United States

---

## Target Sectors

| Sector | Notes |
|--------|-------|
| National Security & International Affairs | Government, diplomatic entities |
| Space & Defense | Military and defense contractors |
| Energy & Utilities | Power grid, nuclear facilities |
| Finance | Banking, insurance |
| HealthCare & Social Assistance | Medical institutions |
| Public Administration | Government agencies |
| Chemical & Pharmaceutical | Pharma companies |
| Manufacturing | Industrial sector |
| Air Transportation | Airlines, aerospace |
| Telecommunications | ISPs, telecom providers |
| Information Services | IT, technology |
| Professional & Technical Services | Consulting firms |
| Aircraft Manufacturing | Aviation industry |
| Travel Agencies | Tourism sector |
| Computer Systems Design | Software companies |

---

## Motivation(s)

- Cyberespionage (geopolitical intelligence, South Asian focus)
- Military and diplomatic intelligence collection
- Strategic intelligence on Pakistan, China, and neighboring states

---

## Associated Malware

| Malware | Platform | Description |
|---------|----------|-------------|
| BADNEWS | Windows | Primary RAT, C2 via dead drops (blogs, RSS feeds) |
| unidentified_102 | Windows | Custom malware (win.unidentified_102) |
| KNSPY | Android | Android spyware (apk.knspy) |
| AsyncRAT | Windows | Open-source RAT used in recent campaigns |
| Ragnatela | Windows | Updated BADNEWS variant |
| BackConfig | Windows | Backdoor with modular plugins |
| TINYTYPHON | Windows | Lightweight backdoor |
| Spyder | Windows | Downloader |

---

## Related CVEs

| CVE | Description |
|-----|-------------|
| CVE-2025-9501 | — |
| CVE-2025-6218 | — |
| CVE-2025-49706 | — |
| CVE-2025-49704 | — |
| CVE-2023-38831 | WinRAR arbitrary code execution (widely exploited) |

---

## Detection Rules

| Rule | Type | Source |
|------|------|--------|
| Potential Browser Data Stealing | SIGMA | Open Source |
| win_atlas_agent_auto | YARA | Open Source |
| rdp_enable_multiple_sessions | YARA | Open Source |
| APT_Patchwork_Tool_CVE_2019_0808_1 | YARA | [StrangerealIntel](https://raw.githubusercontent.com/StrangerealIntel/DailyIOC/master/2020-08-27/APT_Patchwork_Tool_CVE_2019_0808_1.yar) |

---

## Modus Operandi

Patchwork is known for **"patchworking"** — borrowing code from public exploit repos and other APT groups' tools rather than developing fully custom tooling:

1. **Spearphishing**: Emails with malicious Office documents (RTF exploits, macro-enabled docs)
2. **Watering Hole**: Compromised news and government websites
3. **Exploit Chains**: Heavy use of known CVEs (Office, WinRAR, browser exploits)
4. **Copy-Paste Tradecraft**: Tools assembled from leaked exploits, open-source RATs, and code from other APT groups
5. **Dead Drop C2**: BADNEWS uses blog posts and RSS feeds as C2 communication channels
6. **Mobile Targeting**: Android spyware (KNSPY) for mobile surveillance

Post-compromise:
- Keylogging and screenshot capture
- File exfiltration (documents, credentials)
- Browser data theft
- USB drive monitoring
- Persistence via registry keys and scheduled tasks

---

## Campaigns Tracked

_No dedicated campaign directories yet. IOCs available in [iocs.csv](iocs.csv)._

---

## References

| Source | URL |
|--------|-----|
| MITRE ATT&CK | [G0040](https://attack.mitre.org/groups/G0040/) |
| The Hacker News | [Blind Eagle Hacks Colombian](https://thehackernews.com/2025/03/blind-eagle-hacks-colombian.html) |
| StrangerealIntel YARA | [CVE-2019-0808 Rule](https://raw.githubusercontent.com/StrangerealIntel/DailyIOC/master/2020-08-27/APT_Patchwork_Tool_CVE_2019_0808_1.yar) |
