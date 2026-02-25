# Threat Actor Profile — DragonFly (Ghost Blizzard)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** DragonFly, Ghost Blizzard, Energetic Bear, Havex, Iron Liberty, Crouching Yeti, DYMALLOY, Berserk Bear, BROMINE  
**Sponsor:** Russia — FSB Center 16  
**First Seen:** 2010  
**Latest Activity:** December 2025 (destructive attack on Polish power grid)  
**MITRE ATT&CK:** [G0035](https://attack.mitre.org/groups/G0035/)

---

## Target Countries

Poland, United States, Germany, Turkey, Switzerland, United Kingdom, Canada, France, Nordic countries (Sweden, Denmark, Finland, Norway), Ukraine, other NATO member states

---

## Target Sectors

| Sector | Notes |
|--------|-------|
| Energy & Electrical Grid | **Primary target** — power plants, substations, GCPs |
| Nuclear | Nuclear power facilities |
| Water | Water treatment and distribution |
| Critical Manufacturing | Industrial control systems |
| Aviation | Airport infrastructure |
| Commercial Facilities | Large-scale commercial operations |
| Government | Government agencies in NATO countries |

---

## Motivation(s)

- Cyberespionage (long-term intelligence collection on critical infrastructure)
- Pre-positioning for destructive operations (ICS/SCADA access)
- **Destructive cyber warfare** (first confirmed: Polish grid attack, Dec 2025)

---

## Toolset

| Tool | Type | Description |
|------|------|-------------|
| DynoWiper | Wiper | Mersenne Twister PRNG-based file overwriter targeting HMI systems |
| RTU Wiper | Firmware Wiper | Overwrites RTU firmware with corrupted ELF (0xFF entry point) |
| Havex | RAT | ICS-focused RAT with OPC scanning module (legacy) |
| Backdoor.Oldrea | Backdoor | Custom backdoor for ICS environments |
| SecretsDump | Credential Tool | SAM/NTDS/LSA credential dumping |
| Mimikatz | Credential Tool | Credential extraction and Kerberos manipulation |
| CrackMapExec | Pentest Tool | Lateral movement and credential testing |
| PsExec | Execution Tool | Remote command execution |
| Hydra | Brute Force | Password brute-forcing |
| ScreenUtil (scr.exe) | Recon | Screenshot capture utility |
| Web Shells | Persistence | Deployed on public-facing Exchange/web servers |

---

## Key Differentiators

- **Only known Russian cyber warfare unit focused on NATO critical infrastructure** (vs. Sandworm/GRU focused on Ukraine)
- **First destructive cyberattack** on a NATO country's energy grid (Poland, Dec 2025)
- Deep ICS/SCADA expertise — targets HMI systems, RTUs, SCADA networks
- Supply chain compromise capability (trojanized ICS vendor software)
- Diamond Ticket Kerberos attack capability
- Extensive use of FortiGate VPN exploitation for initial access

---

## Campaigns Tracked

| Campaign | Period | Tooling | Targets | Source |
|----------|--------|---------|---------|--------|
| [Polish Grid Attack](Campaigns/2025-12_PolishGrid/) | Dec 2025 | DynoWiper, RTU Wiper, SecretsDump | Polish electrical grid, CHP plant | Truesec, CERT.PL |

---

## Modus Operandi

### Initial Access
- Spearphishing with Office attachments (credential harvesting via SMB forced auth)
- Exploitation of public-facing services: Citrix (CVE-2019-19781), Exchange (CVE-2020-0688), Fortinet VPN (CVE-2018-13379)
- Strategic Web Compromise (watering holes) with custom exploit kits
- Supply chain compromise (trojanized ICS software on vendor app stores)
- FortiGate VPN local account abuse

### Persistence & Lateral Movement
- Web shells on Exchange/web servers
- Registry Run keys, scheduled tasks
- SMB administrative shares (enabled via PowerShell)
- Account creation disguised as backup/service accounts
- GPO modification for wiper distribution
- Diamond Ticket Kerberos attacks

### Destructive Operations
- DynoWiper: Mersenne Twister PRNG-based file destruction on HMI systems
- RTU Wiper: Firmware corruption (0xFF overwrite) rendering devices inoperable
- Distributed via scheduled tasks and GPO "Default Domain Policy" modification
- Data exfiltration via PowerShell Invoke-RestMethod HTTP POST

---

## References

| Source | URL | Date |
|--------|-----|------|
| Truesec | [Detecting Russian Threats to Critical Energy Infrastructure](https://www.truesec.com/hub/blog/detecting-russian-threats-to-critical-energy-infrastructure) | 2026-02-09 |
| CERT.PL | [Energy Sector Incident Report 2025](https://cert.pl/uploads/docs/CERT_Polska_Energy_Sector_Incident_Report_2025.pdf) | 2025 |
| CISA | [AA20-296A: Russian State-Sponsored APT](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-296a) | 2020 |
| CISA | [Russian Government Cyber Activity Targeting Energy](https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors) | 2018 |
| Sophos | [Resurgent Iron Liberty Targeting Energy Sector](https://www.sophos.com/en-us/research/resurgent-iron-liberty-targeting-energy-sector) | — |
| Broadcom/Symantec | [DragonFly Threat Against Western Energy Suppliers](https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers) | — |
| MITRE ATT&CK | [G0035](https://attack.mitre.org/groups/G0035/) | v17 |
