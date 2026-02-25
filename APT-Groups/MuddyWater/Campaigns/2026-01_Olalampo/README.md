# Operation Olalampo — MuddyWater Campaign

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Concluded-orange)
![Attribution](https://img.shields.io/badge/Attribution-High_Confidence-red)

| Field | Value |
|-------|-------|
| **Campaign Name** | Operation Olalampo |
| **Threat Actor** | MuddyWater (TA450 / Seedworm / MERCURY / Static Kitten) |
| **Sponsor** | Iran — MOIS (Ministry of Intelligence and Security) |
| **First Observed** | 2025-10-06 (infrastructure reuse) |
| **Active Phase** | 2026-01-26 — 2026-02-15 |
| **Region** | MENA |
| **Targets** | Energy, Marine Services, Healthcare, System Integrators, Individuals of Interest |
| **Attribution Confidence** | High |
| **Source** | Group-IB Threat Intelligence, [THN Coverage](https://thehackernews.com/2026/02/muddywater-targets-mena-organizations.html) |
| **MITRE ATT&CK** | See [mitre_attack.md](mitre_attack.md) |

## Summary

MuddyWater launched Operation Olalampo in late January 2026, deploying four new malware families through spear-phishing with malicious Office documents. The campaign introduced **CHAR** (Rust backdoor using Telegram bot C2), **GhostFetch** (first-stage downloader), **GhostBackDoor** (sophisticated backdoor with AES-encrypted C2 and French-named API endpoints), and **HTTP_VIP** (downloader deploying AnyDesk RMM). AI-assisted development was detected in the CHAR backdoor. Persian keyboard layout artifacts and developer usernames (DontAsk, Jacob) were exposed through Telegram bot logs. Infrastructure overlap with prior MuddyWater operations dating back to October 2025 was confirmed.

## Malware Arsenal

| Name | Type | Language | C2 Channel | Notes |
|------|------|----------|------------|-------|
| CHAR | Backdoor | Rust | Telegram Bot (`stager_51_bot`) | AI-assisted development, emoji debug strings |
| GhostFetch | Downloader | Native | `promoverse[.]org` | AES-encrypted PE reflective loading, heavy anti-analysis |
| GhostBackDoor | Backdoor | Native | `promoverse[.]org` | AES-encrypted, French-named API endpoints, service persistence |
| HTTP_VIP | Downloader / Backdoor | Native | `codefusiontech[.]org`, `miniquest[.]org` | Deploys AnyDesk, honeypot domain guardrail |

## C2 Infrastructure Timeline

| Domain | Registration | Cert Valid | Operational Window | Backend |
|--------|-------------|------------|-------------------|---------|
| `promoverse[.]org` | 2025-12-21 | 2026-01-07 → 2026-04-07 | ~2026-01-27 → ~2026-01-30 | Werkzeug/3.1.5 Python/3.12.3 |
| `miniquest[.]org` | 2026-01-27 | 2026-02-01 → 2026-05-02 | 2026-02-02 → 2026-02-13 | Werkzeug/3.1.5 Python/3.12.3 |
| `codefusiontech[.]org` | 2026-02-02 | 2026-02-09 → 2026-05-10 | 2026-02-11 → 2026-02-15 | Werkzeug/3.1.5 Python/3.12.3 |

## Telegram C2 Bot

| Field | Value |
|-------|-------|
| **Bot Display Name** | Olalampo |
| **Bot Username** | `stager_51_bot` |
| **Activity Period 1** | 2025-10-06 → 2025-10-12 |
| **Activity Period 2** | 2026-01-28 → 2026-02-01 |

## Threat Actor Artifacts

| Artifact | Value | Context |
|----------|-------|---------|
| Username | `DontAsk` | Office document author + test machine user |
| Username | `Jacob` | PDB paths, Rust build directory, CHAR dev environment |
| Hostname | `desktop-9524r2b` | Test machine |
| Domain | `ultra` | Domain name for user Jacob |
| Keyboard | Persian | `فئعط` = `tmux` on Persian keyboard |

## Quick Links

| Resource | File |
|----------|------|
| Detailed Report | [report.md](report.md) |
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| MITRE ATT&CK Mapping | [mitre_attack.md](mitre_attack.md) |
| Hunting Queries | [fingerprints.txt](fingerprints.txt) |
| Raw Source | [report_raw.txt](report_raw.txt) |

## Key Attribution Evidence

1. FMAPP.dll reverse SOCKS5 proxy matches known MuddyWater tooling
2. Macro logic identical to previous MuddyWater campaigns (UserForm1.TextBox1 decoding, nested-loop sleep evasion)
3. GhostFetch/GhostBackDoor string decoding matches MuddyWater-linked samples
4. CHAR shares development environment with BlackBeard/Archer RAT/RUSTRIC (user `Jacob`, same Rust library paths) — same malware family as RustyWater
5. Infrastructure overlap with `netvigil[.]org` (prior MuddyWater C2)
6. Post-exploitation TTPs consistent with MuddyWater operational patterns

## Changelog

| Date | Change |
|------|--------|
| 2026-02-25 | Added THN coverage reference; linked CHAR ↔ RustyWater |
| 2026-02-23 | THN publishes Olalampo coverage |
| 2026-02-25 | Full structured report created from Group-IB intelligence |
| 2026-02-20 | Group-IB publishes Operation Olalampo blog |
| 2026-01-26 | Campaign first observed |
