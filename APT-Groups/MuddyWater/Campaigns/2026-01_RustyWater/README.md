# RustyWater (Archer RAT / RUSTRIC) — MuddyWater Campaign (Jan 2026)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Active-red)
![Attribution](https://img.shields.io/badge/Attribution-High_Confidence-red)

| Field | Value |
|-------|-------|
| **Campaign Name** | Operation IconCat (Seqrite) / RustyWater campaign |
| **Threat Actor** | MuddyWater (Mango Sandstorm / Static Kitten / TA450) |
| **Active Period** | 2026-01 — ongoing |
| **Region** | Middle East (Israel primary), MSPs, HR, Software Dev |
| **Targets** | Diplomatic, Maritime, Financial, Telecom, IT, MSPs, HR |
| **Attribution Confidence** | High |
| **Sources** | [CloudSEK](https://thehackernews.com/2026/01/muddywater-launches-rustywater-rat-via.html), [Seqrite Labs](https://thehackernews.com/2026/01/muddywater-launches-rustywater-rat-via.html) |

## Summary

MuddyWater deployed a new **Rust-based RAT** called **RustyWater** (also known as **Archer RAT** and **RUSTRIC**) via spearphishing emails masquerading as cybersecurity guidelines. The campaign represents a significant evolution from PowerShell/VBS loaders to compiled Rust implants with asynchronous C2, anti-analysis capabilities, registry persistence, and modular post-compromise expansion. This marks MuddyWater's continued shift away from legitimate RMM tools toward custom malware.

## Attack Chain

```
Spearphishing Email (cybersecurity guidelines lure)
    └── Microsoft Word document
        └── Enable content → VBA macro execution
            └── Deploy RustyWater (Rust binary)
                ├── System info collection
                ├── Security software detection
                ├── Registry persistence
                └── C2 beacon → nomercys.it[.]com
                    ├── File operations
                    └── Command execution
```

## RustyWater Capabilities

| Capability | Description |
|-----------|-------------|
| System Profiling | Collects machine information |
| AV Detection | Detects installed security software |
| Persistence | Windows Registry key |
| C2 Communication | Asynchronous, modular |
| File Operations | Upload / Download |
| Command Execution | Remote command execution |
| Anti-Analysis | Rust binary with evasion techniques |
| Modular Design | Post-compromise capability expansion |

## Tooling Evolution Context

| Era | Primary Tools | Notes |
|-----|---------------|-------|
| Pre-2024 | PowerShell, VBS loaders, POWERSTATS | Script-based, noisy |
| 2024 | Atera, Level, PDQ (RMM) | Legitimate tools for access |
| Late 2024 | MuddyViper/Fooder (C/C++) | Custom compiled tooling |
| 2025 | BugSleep, Phoenix, UDPGangster | Diverse custom arsenal |
| Jan 2026 | RustyWater (Rust) | Low-noise, modular RAT |

## Related Campaigns

- **Operation Olalampo** (Jan 2026): Parallel campaign deploying GhostFetch, CHAR, HTTP_VIP
- **MuddyViper/Fooder** (Sep 2024 – Mar 2025): Previous campaign with C/C++ toolset

## Quick Links

| Resource | File |
|----------|------|
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| MITRE ATT&CK | [mitre_attack.md](mitre_attack.md) |

## Changelog

| Date | Change |
|------|--------|
| 2026-02-25 | Report created from CloudSEK/Seqrite research |
| 2026-01-10 | THN publishes RustyWater analysis |
