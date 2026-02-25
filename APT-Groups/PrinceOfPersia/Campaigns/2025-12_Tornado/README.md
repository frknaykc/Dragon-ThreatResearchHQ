# Tornado v51 — Prince of Persia Campaign (Dec 2025 – Feb 2026)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Active-red)
![Attribution](https://img.shields.io/badge/Attribution-High_Confidence-red)

| Field | Value |
|-------|-------|
| **Campaign** | Prince of Persia Part II — Tornado v51 |
| **Threat Actor** | Prince of Persia (Iranian state-sponsored) |
| **Research Period** | 2025-12-19 — 2026-02-03 |
| **Dormant Period** | 2026-01-08 — 2026-01-25 (Iran internet blackout) |
| **Targets** | India, Germany (based on VT uploads) |
| **Source** | [SafeBreach Labs](https://www.safebreach.com/blog/prince-of-persia-part-ii/) |

## Summary

SafeBreach Labs tracked Prince of Persia's response to their Part I publication (Dec 18, 2025). Within days, the actor replaced all C2 servers, Telegram users, and added RSA verification to prevent researcher impersonation. **Tornado v51** — the latest Foudre variant — was identified with dual C2 (HTTP + Telegram) and a novel **blockchain-based DGA** using Bitcoin `OP_RETURN` data. The actor exploited WinRAR vulnerabilities (CVE-2025-8088/CVE-2025-6218) for initial access. A **strike-back** attempt against researchers using ZZ Stealer → StormKitty was detected. Activity correlation with Iran's January 2026 internet blackout confirmed state sponsorship.

## Attack Chain

```
WinRAR Exploit (CVE-2025-8088 / CVE-2025-6218)
└── SFX archive (masquerades as .doc — "tozihat.doc")
    └── AudioService.exe → dropped to Startup folder
        └── reg7989.dll (TornadoInstaller)
            ├── Avast check
            ├── Scheduled task persistence
            └── AuthFWSnapin.dll (Tornado v51 main DLL)
                ├── DGA C2 resolution (Manual or Blockchain)
                │   ├── Manual: base32 + custom alphabet → 8-char domains
                │   └── Active: blockchain.info → OP_RETURN → deobfuscate domain
                ├── HTTP C2 communication (4 actions: d1, d2, k, s)
                ├── Telegram C2 (sendDocument, getUpdates)
                └── Downloads Tonnerre (password: Hcudhl3hcbgQdpnr3)
```

## C2 Infrastructure

| IP | Role | Active Dates | Domains |
|----|------|-------------|---------|
| 45.80.148.249 | Active C2 (Foudre) | Dec 24, 2025 – present | szzqwggurg.hbmc.net, uiavuflyjqodj.conningstone.net, + 9 more |
| 45.80.148.195 | Abandoned C2 | Oct 12 – Dec 2025 | querylist.online (originally) |
| 45.80.149.3 | C2 (Foudre + Tonnerre) | Dec 28, 2025 – present | lklptttt.space, onnmuoru.privatedns.org, f13.ddnsking.com, t13.ddnsking.com |
| 45.80.149.100 | Historical C2 | Feb – May 2025 | tegfxbnk.site, ejjnhkucbw.ix.tc |
| 45.80.148.35 | Abandoned Tonnerre C2 | — | 92c5d3b3.ddns.net |
| 45.80.148.124 | Historical Tonnerre C2 | Jul – Aug 2025 | xjhdvkoszwdpt.privatedns.org |
| 209.38.92.52 | ZZ Stealer C2 | Active | — |
| 128.199.113.162 | Historical ZZ Stealer C2 | Pre-2022 | — |
| 191.101.130.244 | Phantom Stealer / possible APT33 link | Feb – Mar 2025 | phantomsoftwares.site |
| 104.248.194.233 | AB Metasploit C2 | — | — |

## Telegram Infrastructure

| Asset | Value |
|-------|-------|
| Bot API Key (Tornado) | `7900216285:AAEVjLjt4csUKGanerJuuiDhdsmlUv0yooM` |
| Telegram Group (Tornado) | `sarafraz` (chat_id: 874675833) |
| Original User | @ehsan8999100 (removed Dec 19) |
| Replacement User | @Ehsan66442 |
| Bot API Key (StormKitty 8==3) | `7033932802:AAGEIhL9e0lyUi0vjZnRy3PcwnKJPhSCFWQ` |
| StormKitty Operator | N3cro M4ncer (chat_id: 1126217452) |
| Exfiltration Bot | d00m3rz_bot |
| Historical Bot | quakerz_bot (API: `5444063802:AAFQNx_Hpow_i63EVEkfhenefbLEXQSAzbY`) |

## Quick Links

| Resource | File |
|----------|------|
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| MITRE ATT&CK | [mitre_attack.md](mitre_attack.md) |
