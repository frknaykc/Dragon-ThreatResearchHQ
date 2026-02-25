<p align="center">
  <img src="./logo.png" alt="Dragon Threat Research HQ" width="400"/>
</p>

<h1 align="center">Dragon Threat Research HQ</h1>

<p align="center">
  <b>Comprehensive Threat Intelligence Repository</b><br/>
  Malware Analysis &bull; IOC Feeds &bull; YARA Rules &bull; Hunting Queries &bull; STIX Bundles &bull; MITRE ATT&CK Mappings
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Threats_Tracked-28-blue" alt="Threats"/>
  <img src="https://img.shields.io/badge/Total_IOCs-12,459-orange" alt="IOCs"/>
  <img src="https://img.shields.io/badge/YARA_Rules-18-green" alt="YARA"/>
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License"/>
</p>

---

## Repository Structure

```
Dragon-ThreatResearchHQ/
│
├── APT-Groups/              # State-sponsored threat actor profiles & campaigns
│   ├── APT29-CozyBear/      # Russia — 5,407 IOCs
│   ├── APT39/               # Iran — 51 IOCs
│   ├── BitterAPT/           # South Asia — 19 IOCs
│   ├── DroppingElephant/    # India — 9 IOCs
│   ├── EquationGroup/       # USA — 422 IOCs
│   ├── FIN7/                # Russia — 3,272 IOCs
│   ├── Kimsuky-APT43/       # North Korea — 11 IOCs
│   ├── MuddyWater/          # Iran (MOIS) — 307 IOCs, 6 campaigns
│   ├── RedDelta/            # China — 287 IOCs
│   ├── ScatteredSpider/     # Multi — 214 IOCs
│   ├── SideWinder/          # India — 364 IOCs
│   ├── Storm-1811/          # Unknown — 15 IOCs
│   ├── DragonFly-GhostBlizzard/ # Russia (FSB) — 8 IOCs, 2 YARA (DynoWiper)
│   ├── PrinceOfPersia/       # Iran — 95 IOCs (Tornado, Foudre, Tonnerre)
│   ├── UNC5221/             # China
│   ├── VoidArachne-SilverFox/ # China — 6 IOCs (ValleyRAT/Winos 4.0)
│   └── VoltTyphoon/         # China — 194 IOCs
│
├── Malware/                 # Malware families by category
│   ├── RATs/                # EtherRAT (92), MoonriseRAT
│   ├── Stealers/            # LummaStealer (817), OdysseyStealer (51), ...
│   ├── Backdoors/           # Brickstorm (35)
│   ├── Loaders/             # AeternumLoader (63), Phoenix
│   ├── Miners/              # XMRig-BYOVD (cryptojacking)
│   └── Wipers/              # DynoWiper + RTU Wiper (ICS/OT)
│
├── C2-Frameworks/           # C2 framework analysis
│   ├── CobaltStrike/        # 1,235 IOCs, beacon configs, YARA
│   └── VenusC2/             # 5 IOCs
│
├── Campaigns/               # Standalone campaigns (not actor-specific)
│   └── 2024-06_RegreSSHion_CVE-2024-6387/
│
├── Detection-Rules/         # Generic detection rules
│   └── Yara/                # xor_hunter.yar, office_startup_anomaly.yar
│
├── feeds/                   # Aggregated IOC feeds (SIEM-ready)
│   ├── all_iocs.csv         # 12,459 IOCs — master CSV
│   ├── domains.txt          # 2,398 domains
│   ├── ips.txt              # 2,679 IPs
│   ├── hashes.txt           # 6,608 hashes (SHA256/SHA1/MD5)
│   ├── urls.txt             # 413 URLs
│   └── cves.txt             # 119 CVEs
│
├── scripts/                 # Automation
│   └── aggregate_iocs.py    # IOC aggregation & feed generation
│
├── Templates/               # Standardized templates for new entries
├── Resources/               # Reference material
├── index.json               # Machine-readable threat index
├── CONTRIBUTING.md           # Contribution guidelines
├── CODE_OF_CONDUCT.md        # Code of conduct
└── LICENSE                   # MIT License
```

---

## Threat Index

### APT Groups (17)

| Group | Origin | IOCs | Campaigns | YARA | Report |
|-------|--------|-----:|:---------:|:----:|--------|
| [MuddyWater](APT-Groups/MuddyWater/) | Iran | 307 | 6 | — | [Profile](APT-Groups/MuddyWater/README.md) |
| [APT29 / Cozy Bear](APT-Groups/APT29-CozyBear/) | Russia | 5,407 | — | — | — |
| [FIN7](APT-Groups/FIN7/) | Russia | 3,272 | — | — | — |
| [Equation Group](APT-Groups/EquationGroup/) | USA | 422 | — | — | — |
| [SideWinder](APT-Groups/SideWinder/) | India | 364 | — | — | — |
| [Red Delta](APT-Groups/RedDelta/) | China | 287 | — | — | — |
| [Scattered Spider](APT-Groups/ScatteredSpider/) | Multi | 214 | — | — | — |
| [Volt Typhoon](APT-Groups/VoltTyphoon/) | China | 194 | — | — | — |
| [APT39](APT-Groups/APT39/) | Iran | 51 | — | — | — |
| [Bitter APT](APT-Groups/BitterAPT/) | South Asia | 19 | 1 | — | [Profile](APT-Groups/BitterAPT/README.md) |
| [Storm-1811](APT-Groups/Storm-1811/) | Unknown | 15 | — | — | — |
| [Kimsuky / APT43](APT-Groups/Kimsuky-APT43/) | N. Korea | 11 | 1 | — | [Profile](APT-Groups/Kimsuky-APT43/README.md) |
| [DragonFly / Ghost Blizzard](APT-Groups/DragonFly-GhostBlizzard/) | Russia | 8 | 1 | [2 rules](APT-Groups/DragonFly-GhostBlizzard/Campaigns/2025-12_PolishGrid/yara/) | [Profile](APT-Groups/DragonFly-GhostBlizzard/README.md) |
| [Dropping Elephant](APT-Groups/DroppingElephant/) | India | 9 | — | — | [Profile](APT-Groups/DroppingElephant/README.md) |
| [Prince of Persia](APT-Groups/PrinceOfPersia/) | Iran | 95 | 1 | — | [Profile](APT-Groups/PrinceOfPersia/README.md) |
| [Void Arachne / Silver Fox](APT-Groups/VoidArachne-SilverFox/) | China | 6 | — | — | [Profile](APT-Groups/VoidArachne-SilverFox/README.md) |
| [UNC5221](APT-Groups/UNC5221/) | China | — | — | — | [Profile](APT-Groups/UNC5221/README.md) |

### MuddyWater Campaigns (Deep-Dive)

| Campaign | Period | Tooling | IOCs | Report |
|----------|--------|---------|-----:|--------|
| [MuddyViper / Snakes by the Riverbank](APT-Groups/MuddyWater/Campaigns/2024-09_MuddyViper/) | Sep 2024 – Mar 2025 | Fooder, MuddyViper, CE-Notes, LP-Notes, Blub, go-socks5 | 75 | [README](APT-Groups/MuddyWater/Campaigns/2024-09_MuddyViper/README.md) |
| [Operation Olalampo](APT-Groups/MuddyWater/Campaigns/2026-01_Olalampo/) | Jan – Feb 2026 | CHAR, GhostFetch, GhostBackDoor, HTTP_VIP | 58 | [README](APT-Groups/MuddyWater/Campaigns/2026-01_Olalampo/README.md) |
| [RustyWater](APT-Groups/MuddyWater/Campaigns/2026-01_RustyWater/) | Jan 2026 – | RUSTRIC / Archer RAT | 1 | [README](APT-Groups/MuddyWater/Campaigns/2026-01_RustyWater/README.md) |
| [DHCSpy](APT-Groups/MuddyWater/Campaigns/2023-07_DHCSpy/) | Jul 2023 | DHCSpy Android Spyware | 19 | [README](APT-Groups/MuddyWater/Campaigns/2023-07_DHCSpy/README.md) |
| [Sep 2024 Campaign](APT-Groups/MuddyWater/Campaigns/2024-09_Campaign/) | Sep 2024 | Various | 75 | — |
| [2025 Campaign](APT-Groups/MuddyWater/Campaigns/2025_MuddyWater/) | 2025 | Various | 8 | — |

### Malware Families (13)

| Malware | Type | IOCs | YARA | Report |
|---------|------|-----:|:----:|--------|
| [Lumma Stealer](Malware/Stealers/LummaStealer/) | Stealer | 817 | [1 rule](Malware/Stealers/LummaStealer/yara/) | — |
| [EtherRAT](Malware/RATs/EtherRAT/) | RAT | 92 | — | [README](Malware/RATs/EtherRAT/README.md) |
| [Aeternum Loader](Malware/Loaders/AeternumLoader/) | Loader | 63 | [1 rule](Malware/Loaders/AeternumLoader/yara/) | [README](Malware/Loaders/AeternumLoader/README.md) |
| [Odyssey Stealer](Malware/Stealers/OdysseyStealer/) | Stealer/RAT | 51 | — | [README](Malware/Stealers/OdysseyStealer/README.md) |
| [Brickstorm](Malware/Backdoors/Brickstorm/) | Backdoor | 35 | [9 rules](Malware/Backdoors/Brickstorm/yara/) | — |
| [Snake Keylogger](Malware/Stealers/SnakeKeylogger/) | Keylogger | 19 | — | — |
| [Meduza Stealer](Malware/Stealers/MeduzaStealer/) | Stealer | 13 | — | — |
| [BLX Stealer](Malware/Stealers/BLXStealer/) | Stealer | 2 | — | — |
| [Moonrise RAT](Malware/RATs/MoonriseRAT/) | RAT | — | — | — |
| [Phoenix](Malware/Loaders/Phoenix/) | Loader/Backdoor | — | — | [README](Malware/Loaders/Phoenix/README.md) |
| [XMRig BYOVD](Malware/Miners/XMRig-BYOVD/) | Miner | 4 | — | [README](Malware/Miners/XMRig-BYOVD/README.md) |
| [DynoWiper](Malware/Wipers/DynoWiper/) | Wiper (ICS) | 4 | [2 rules](Malware/Wipers/DynoWiper/yara/) | [README](Malware/Wipers/DynoWiper/README.md) |

### C2 Frameworks (2)

| Framework | IOCs | Beacon Configs | YARA | C2 List |
|-----------|-----:|:--------------:|:----:|---------|
| [Cobalt Strike](C2-Frameworks/CobaltStrike/) | 1,235 | [configs/](C2-Frameworks/CobaltStrike/Beacon-Configs/) | [3 rules](C2-Frameworks/CobaltStrike/yara/) | [c2_list.md](C2-Frameworks/CobaltStrike/c2_list.md) |
| [Venus C2](C2-Frameworks/VenusC2/) | 5 | — | — | [README](C2-Frameworks/VenusC2/README.md) |

### Standalone Campaigns (1)

| Campaign | Date | IOCs | Description |
|----------|------|-----:|-------------|
| [RegreSSHion CVE-2024-6387](Campaigns/2024-06_RegreSSHion_CVE-2024-6387/) | Jun 2024 | 31 | OpenSSH RCE vulnerability exploitation |

### Detection Rules (YARA)

| Rule | Target | Path |
|------|--------|------|
| XOR Hunter | XOR-encoded payloads | [xor_hunter.yar](Detection-Rules/Yara/xor_hunter.yar) |
| Office Startup Anomaly | Suspicious Office startup files | [office_startup_anomaly.yar](Detection-Rules/Yara/office_startup_anomaly.yar) |
| Cobalt Strike (3 rules) | CS beacons, syscalls, obfuscation | [yara/](C2-Frameworks/CobaltStrike/yara/) |
| Brickstorm (9 rules) | Brickstorm + Mandiant hunting | [yara/](Malware/Backdoors/Brickstorm/yara/) |
| Lumma Stealer | Lumma variants | [yara/](Malware/Stealers/LummaStealer/yara/) |
| Aeternum Loader | Aeternum panel/loader | [yara/](Malware/Loaders/AeternumLoader/yara/) |
| DynoWiper Mersenne | Mersenne Twister PRNG-based wiper (HMI) | [yara/](APT-Groups/DragonFly-GhostBlizzard/Campaigns/2025-12_PolishGrid/yara/) |
| RTU Firmware Wiper | ELF with 0xFF entry point (firmware wiper) | [yara/](APT-Groups/DragonFly-GhostBlizzard/Campaigns/2025-12_PolishGrid/yara/) |

---

## IOC Feeds (SIEM-Ready)

All IOCs across the repository are aggregated into flat files for direct import into SIEM, TIP, firewall, or DNS sinkhole systems.

| Feed | Entries | Format | Description |
|------|--------:|--------|-------------|
| [`feeds/all_iocs.csv`](feeds/all_iocs.csv) | 12,459 | CSV | Master file — all IOCs with metadata |
| [`feeds/domains.txt`](feeds/domains.txt) | 2,398 | Flat | One domain per line |
| [`feeds/ips.txt`](feeds/ips.txt) | 2,679 | Flat | One IP per line |
| [`feeds/hashes.txt`](feeds/hashes.txt) | 6,608 | Flat | SHA256 / SHA1 / MD5 |
| [`feeds/urls.txt`](feeds/urls.txt) | 413 | Flat | Malicious URLs |
| [`feeds/cves.txt`](feeds/cves.txt) | 119 | Flat | CVE identifiers |
| [`index.json`](index.json) | 23 | JSON | Machine-readable threat index |

Each APT group and malware family also has its own `iocs_all.csv` that merges all campaign IOCs.

### Usage

```bash
# Import domains into DNS sinkhole
curl -sL https://raw.githubusercontent.com/<org>/Dragon-ThreatResearchHQ/main/feeds/domains.txt

# Import IPs into firewall blocklist
curl -sL https://raw.githubusercontent.com/<org>/Dragon-ThreatResearchHQ/main/feeds/ips.txt

# Regenerate all feeds after adding new IOCs
python3 scripts/aggregate_iocs.py
```

---

## How Each Threat is Organized

Every threat directory follows a consistent structure:

```
ThreatName/
├── README.md           # Threat card — metadata, summary, quick links
├── report.md           # Detailed analysis report
├── iocs.csv            # IOCs (type, value, description, threat_actor, campaign, confidence, source, tags)
├── iocs.stix.json      # STIX 2.1 bundle
├── mitre_attack.md     # MITRE ATT&CK technique mapping
├── fingerprints.txt    # Shodan / Censys / FOFA / Google Dork / SIEM queries
├── yara/               # Threat-specific YARA rules
└── screenshots/        # Panel, sandbox, phishing page screenshots
```

> See [Templates/THREAT_TEMPLATE/](Templates/THREAT_TEMPLATE/) for ready-to-use templates.
> See [Templates/IOC_CSV_HEADER.md](Templates/IOC_CSV_HEADER.md) for IOC CSV column definitions.

---

## Workflow: Adding New Threats

```
1. Copy Templates/THREAT_TEMPLATE/ → appropriate category directory
2. Fill in README.md, report.md, iocs.csv, mitre_attack.md
3. Run: python3 scripts/aggregate_iocs.py
4. Feeds, iocs_all.csv, and index.json are auto-updated
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## Purpose

| Goal | Description |
|------|-------------|
| **Threat Intelligence** | Structured IOCs, STIX bundles, and hunting queries for rapid detection |
| **SOC Integration** | CSV and flat-file feeds ready for SIEM / TIP / firewall import |
| **Research & Education** | Detailed reports and ATT&CK mappings for understanding threat actors |
| **Community** | Standardized templates make contribution straightforward |

---

## Disclaimer

This repository is maintained for **educational and research purposes only**. The misuse of any information contained herein for malicious purposes is strictly prohibited. Always follow legal and ethical guidelines when handling threat intelligence data.

---

## License

This project is licensed under the [MIT License](LICENSE).
