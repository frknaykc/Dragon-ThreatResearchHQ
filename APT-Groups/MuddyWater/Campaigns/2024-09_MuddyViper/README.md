# MuddyViper / Fooder — MuddyWater Campaign (Sep 2024 – Mar 2025)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Concluded-orange)
![Attribution](https://img.shields.io/badge/Attribution-High_Confidence-red)

| Field | Value |
|-------|-------|
| **Campaign Name** | Snakes by the Riverbank |
| **Threat Actor** | MuddyWater (Mango Sandstorm / TA450) |
| **Active Period** | 2024-09-30 — 2025-03-18 |
| **Region** | Israel (primary), Egypt |
| **Targets** | Engineering, Local Government, Manufacturing, Technology, Transportation, Utilities, Universities |
| **Cooperation** | Joint sub-campaign with Lyceum (OilRig subgroup) in Jan–Feb 2025 |
| **Attribution Confidence** | High |
| **Source** | [ESET Research](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/) |

## Summary

ESET documented an unprecedented advancement in MuddyWater's toolset. The campaign deployed **Fooder**, a C/C++ loader masquerading as the classic Snake game to delay execution and evade analysis, which reflectively loads **MuddyViper**, a new C/C++ backdoor with 20 commands supporting reverse shells, file operations, credential theft via fake Windows Security dialogs, and browser data theft via embedded HackBrowserData. The group adopted **CNG** (Windows next-gen cryptographic API) for AES-CBC encryption — unique among Iran-aligned groups. Additional tools include **CE-Notes** (browser-data stealer), **LP-Notes** (credential stealer), **Blub** (browser-data stealer), and customized **go-socks5** reverse tunnels internally named "ESETGO". A joint sub-campaign with **Lyceum** (OilRig subgroup) targeted an Israeli manufacturing company, suggesting MuddyWater may act as an initial access broker.

## New Toolset

| Tool | Type | Language | Description |
|------|------|----------|-------------|
| Fooder | Loader | C/C++ | Reflective loader, Snake game masquerade, AES-decrypts embedded payload |
| MuddyViper | Backdoor | C/C++ | 20 commands, CNG AES-CBC C2, credential theft, HackBrowserData |
| CE-Notes | Browser Stealer | C/C++ | Steals Chromium app-bound encryption keys, outputs to `ce-notes.txt` |
| LP-Notes | Credential Stealer | C/C++ | Fake Windows Security dialog, outputs to `lp-notes.txt` |
| Blub | Browser Stealer | C/C++ | Chrome/Edge/Firefox/Opera credential theft with SQLite |
| go-socks5 (ESETGO) | Reverse Tunnel | Go | yamux + go-socks5, SSL/TLS authenticated reverse proxy |

## MuddyViper C2 Protocol

- **Transport:** HTTPS GET (port 443, WinHTTP with SSL/TLS)
- **Encryption:** AES-CBC via CNG API (shared key across samples)
- **Command delivery:** HTTP status code = command ID, body = arguments
- **Data format:** `<computer_name>/<username>*<data>` before encryption
- **User-Agent:** `A WinHTTP Example Program/1.0`
- **Default beacon:** 60 seconds (configurable via command 700)

## MuddyViper Commands (20 total)

| ID | Action |
|----|--------|
| 200 | Request command |
| 207 | Steal browser data (HackBrowserData → CacheDump.zip) |
| 300-302 | Launch reverse shell (custom/cmd.exe/PowerShell) |
| 350-352 | Reverse shell control (sleep/configure/input) |
| 400-401 | File upload (chunked) |
| 500-501 | File download (chunked) |
| 700 | Configure beacon interval |
| 800 | Enumerate security tools (150+ process list) |
| 805 | Fake Windows Security dialog → credential theft |
| 806 | Set persistence (scheduled task: ManageOnDriveUpdater) |
| 900 | Uninstall self |
| 905 | Terminate process |
| 906 | Relaunch self |

## Persistence Mechanisms

| Method | Detail |
|--------|--------|
| Startup Folder | Registry: `HKCU\...\User Shell Folders\Startup` → `%LOCALAPPDATA%\Microsoft\Windows\PPBCompatCache\ManagerCache` |
| Scheduled Task | `ManageOnDriveUpdater` |
| RMM Tools | Atera, Level, PDQ, SimpleHelp installed in `%PROGRAMFILES%` |

## Lyceum Cooperation (Jan–Feb 2025)

MuddyWater initiated access via Syncro RMM spearphishing → installed PDQ → deployed custom Mimikatz loader (disguised as `.txt` certificate files) → credentials handed to Lyceum for lateral operations. Targeted: Israeli manufacturing sector.

## Quick Links

| Resource | File |
|----------|------|
| IOCs (CSV) | [iocs.csv](iocs.csv) |

## Changelog

| Date | Change |
|------|--------|
| 2026-02-25 | Report created from ESET research |
| 2025-12-02 | ESET publishes "Snakes by the Riverbank" |
| 2025-03-18 | Campaign concluded |
| 2024-09-30 | Campaign began |
