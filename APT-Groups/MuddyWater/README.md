# Threat Actor Profile — MuddyWater

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** TEMP.Zagros, Seedworm, Static Kitten, Mango Sandstorm, MUDDYCOAST, Earth Vetala, TA450, Boggy Serpens, MERCURY  
**Sponsor:** Iran — Ministry of Intelligence and Security (MOIS)  
**First Seen:** 2017  
**Latest Activity:** February 2026 (Operation Olalampo, RustyWater, MuddyViper)  
**Group-IB Ranking:** #6 among Top 10 Masked Actors (2025)  
**Source:** [Group-IB Masked Actors](https://www.group-ib.com/masked-actors/muddywater/), [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/)

---

## Languages
- English
- Persian (Farsi)
- Arabic
- Hebrew

---

## Geography / Operational Focus
- Middle East (Israel primary target)
- Turkey
- Egypt
- Azerbaijan
- Pakistan
- North Africa (MENA)
- NATO-affiliated nations
- United States
- United Kingdom

---

## Top Industries Targeted
- Telecommunications
- Government (Local & National)
- Critical Infrastructure & Utilities
- Energy & Oil/Gas
- Engineering & Manufacturing
- Defense & Military
- Education & Universities
- Transportation
- Information Technology & MSPs
- Diplomatic & Maritime
- Financial & Banking
- Healthcare

---

## Motivation(s)
- Cyberespionage
- Intelligence gathering
- Tactical disruption
- Initial access brokering (cooperation with Lyceum/OilRig)

---

## Skillset
- Linux / Windows / macOS
- Apache / Nginx
- Python / Golang / Rust / C/C++ / PowerShell / VBA
- AWS / Cloud infrastructure
- RMM (Remote Monitoring & Management)
- Spearphishing & Social Engineering
- Reflective loading & In-memory execution
- CNG (Next-gen Windows Cryptographic API)
- AI-assisted malware development (Gemini / generative AI)
- Telegram Bot API for C2
- Reverse proxy tunneling (SOCKS5)

---

## Toolset (Comprehensive)

### Custom Malware

| Tool | Type | Language | First Seen | Notes |
|------|------|----------|------------|-------|
| MuddyViper | Backdoor | C/C++ | 2024-09 | 20 commands, CNG AES-CBC, HackBrowserData integration |
| Fooder | Loader | C/C++ | 2024-09 | Reflective loader, Snake game masquerade |
| CHAR | Backdoor | Rust | 2026-01 | Telegram bot C2, AI-assisted development |
| RustyWater (Archer RAT / RUSTRIC) | RAT | Rust | 2026-01 | Modular, async C2, registry persistence |
| GhostFetch | Downloader | Native | 2026-01 | AES-encrypted PE loading, anti-analysis |
| GhostBackDoor | Backdoor | Native | 2026-01 | AES C2, French-named API endpoints |
| HTTP_VIP | Downloader | Native | 2026-01 | Deploys AnyDesk, honeypot guardrail |
| Phoenix | Backdoor | — | 2025 | v4 deployed via Word macro |
| BugSleep (MuddyRot) | Backdoor | — | 2024 | Sleep-based evasion |
| UDPGangster | Backdoor | — | 2024 | UDP-based C2 |
| CE-Notes | Browser Stealer | C/C++ | 2024 | Chromium app-bound encryption key theft |
| LP-Notes | Credential Stealer | C/C++ | 2024 | Fake Windows Security dialog |
| Blub | Browser Stealer | C/C++ | 2024-09 | Chrome/Edge/Firefox/Opera, SQLite |
| POWERSTATS | Backdoor | PowerShell | 2017 | Legacy, still occasionally used |
| Blackout | Backdoor | — | 2023 | — |
| Small Sieve | Backdoor | — | 2022 | — |
| Mori | Backdoor | — | 2022 | — |
| StealthCache | Tool | — | 2024 | — |
| FakeUpdate | Loader | — | 2024 | — |
| LiteInject | Loader | — | 2024 | — |
| CannonRat | RAT | — | 2024 | — |
| SilentShell | Shell | — | 2024 | — |
| PowerGUI | Tool | PowerShell | 2024 | — |
| Chromium_Stealer | Stealer | — | 2024 | — |

### Open-Source & Legitimate Tools

| Tool | Type | Usage |
|------|------|-------|
| Atera | RMM | Initial access & persistence |
| Level | RMM | Initial access & persistence |
| PDQ | RMM | Post-compromise deployment |
| SimpleHelp | RMM | Remote access |
| Action1 | RMM | Remote access |
| ScreenConnect | RMM | Remote access |
| Syncro | RMM | Initial access (Lyceum cooperation) |
| AnyDesk | RMM | Deployed by HTTP_VIP |
| HackBrowserData | Stealer | Browser data theft (embedded in Fooder) |
| go-socks5 (ESETGO) | Reverse Tunnel | yamux + SOCKS5 proxy |
| LaZagne | Credential Tool | Password recovery |
| CrackMapExec | Pentest | Lateral movement |
| Mimikatz | Credential Tool | Custom loader variant |

---

## Campaigns Tracked

| Campaign | Period | Tooling | Targets | Source |
|----------|--------|---------|---------|--------|
| [MuddyViper / Snakes by the Riverbank](Campaigns/2024-09_MuddyViper/) | Sep 2024 – Mar 2025 | Fooder, MuddyViper, CE-Notes, LP-Notes, Blub, go-socks5 | Israel, Egypt (Engineering, Gov, Manufacturing, Utilities, Universities) | ESET |
| [Operation Olalampo](Campaigns/2026-01_Olalampo/) | Jan – Feb 2026 | CHAR, GhostFetch, GhostBackDoor, HTTP_VIP | MENA (Energy, Marine, Healthcare) | Group-IB, THN |
| [RustyWater](Campaigns/2026-01_RustyWater/) | Jan 2026 – ongoing | RustyWater (RUSTRIC) | ME (Diplomatic, Maritime, Financial, Telecom, IT, MSPs) | CloudSEK, Seqrite |
| [DHCSpy](Campaigns/2023-07_DHCSpy/) | Jul 2023 | DHCSpy Android spyware | Mobile targets, MENA | Shindan |
| [Sep 2024 Campaign](Campaigns/2024-09_Campaign/) | Sep 2024 | Various | — | — |

---

## Cooperation with Other Groups

### Lyceum (OilRig Subgroup) — Jan/Feb 2025
MuddyWater initiated access via Syncro RMM spearphishing → installed PDQ → deployed custom Mimikatz loader → credentials handed to Lyceum for lateral operations in Israeli manufacturing sector. This suggests MuddyWater may serve as an **initial access broker** for other Iran-aligned groups.

---

## Threat Actor Write-up

MuddyWater is a sophisticated Iranian cyberespionage group active since at least 2017, subordinate to the Ministry of Intelligence and Security (MOIS). The group ranked #6 among Group-IB's Top 10 Masked Actors for 2025, demonstrating sustained and significant operational tempo.

The group's primary motivations are cyberespionage and intelligence collection. MuddyWater targets a broad range of sectors including government, telecommunications, energy, critical infrastructure, defense, and manufacturing, with operations concentrated in the Middle East (Israel as the primary target), North Africa, South Asia, and NATO-affiliated countries.

MuddyWater has undergone significant tooling evolution: from PowerShell/VBS-based tools (2017–2023), through legitimate RMM tool abuse (2023–2024), to sophisticated custom malware in C/C++ (MuddyViper, Fooder) and Rust (CHAR, RustyWater) in 2024–2026. The group has adopted AI-assisted development (detected in CHAR backdoor), CNG cryptographic API usage (unique among Iran-aligned groups), and Telegram bot-based C2 infrastructure.

Cooperation with Lyceum (OilRig subgroup) in early 2025 suggests an expanded role as an initial access broker, providing entry points for other Iranian APT operations.

---

## Modus Operandi

MuddyWater primarily relies on **spearphishing** to gain initial access, using:
- PDF attachments linking to RMM installers on OneHub, Egnyte, or Mega
- Microsoft Word/Excel documents with VBA macros
- Cybersecurity guideline lures, flight ticket themes, energy company impersonation

Post-compromise operations include:
1. **Persistence**: Registry Run keys, Startup folder manipulation, scheduled tasks, Windows services, RMM tool installation
2. **Credential Theft**: Fake Windows Security dialogs (MuddyViper, LP-Notes), browser data theft (CE-Notes, Blub, HackBrowserData), Mimikatz
3. **C2 Communication**: HTTPS with AES-CBC encryption, Telegram bots, reverse SOCKS5 proxies
4. **Evasion**: Reflective code loading, time-based evasion (Snake game delays), string obfuscation, dynamic API resolution, debugger detection
5. **Exfiltration**: Data chunking over C2 channel, staged local files for RMM tool retrieval

The group has shown increasing sophistication while retaining some operational immaturity (verbose status messages, PDB paths left intact, predictable spearphishing patterns).

---

## References

| Source | URL | Date |
|--------|-----|------|
| ESET Research | [Snakes by the Riverbank](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/) | 2025-12-02 |
| Group-IB | [Masked Actors: MuddyWater](https://www.group-ib.com/masked-actors/muddywater/) | 2025 |
| Group-IB | [SimpleHarm: Tracking MuddyWater](https://www.group-ib.com/blog/muddywater-infrastructure/) | 2026 |
| The Hacker News | [RustyWater RAT](https://thehackernews.com/2026/01/muddywater-launches-rustywater-rat-via.html) | 2026-01-10 |
| The Hacker News | [GhostFetch, CHAR, HTTP_VIP](https://thehackernews.com/2026/02/muddywater-targets-mena-organizations.html) | 2026-02-23 |
| MITRE ATT&CK | [G0069](https://attack.mitre.org/groups/G0069/) | v17 |
| Shindan | [DHCSpy Analysis](https://shindan.io/blog/dhcspy-discovering-the-iranian-apt-muddywater) | 2023 |
