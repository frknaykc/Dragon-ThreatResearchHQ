# Threat Actor Profile — Prince of Persia

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)

**Aliases:** Prince of Persia  
**Sponsor:** Iran — State-sponsored (confirmed by internet blackout correlation, Jan 2026)  
**First Seen:** ~2017 (tracked by SafeBreach since 2019)  
**Latest Activity:** February 2026  
**Possible Links:** Educated Manticore (Iranian APT), APT33 (via Remcos/VBS overlap)

---

## Target Countries

India, Germany, Israel (suspected), Iran (domestic surveillance)

---

## Target Sectors

| Sector | Notes |
|--------|-------|
| Government | State entities, diplomatic targets |
| General Population | Iranian citizens (domestic surveillance) |
| Security Researchers | Active strike-back against analysts |

---

## Motivation(s)

- Cyberespionage (domestic & foreign intelligence)
- Surveillance of Iranian citizens
- Counter-intelligence (active strike-back against security researchers)

---

## Toolset

| Tool | Type | Language | Description |
|------|------|----------|-------------|
| Foudre (v34, v50) | Backdoor/Downloader | — | First-stage malware, DGA-based C2, Telegram exfiltration |
| Tonnerre (v12–v17, v50) | Backdoor | — | Second-stage malware, downloaded by Foudre |
| Tornado (v51) | Backdoor | — | Latest variant (Foudre family), dual C2 (HTTP + Telegram), blockchain DGA |
| ZZ Stealer (v3.81, v3.82) | Infostealer | .NET | First-stage recon, screenshot capture, desktop file theft |
| StormKitty (8==3 fork) | Infostealer | .NET | Second-stage stealer (forked from open-source StormKitty) |
| Phantom Stealer (v3.5.0) | Infostealer | .NET | Rebrand of StormKitty, commercial version |
| MaxPinner (v5, v8) | Tool | — | Older tooling (2018–2021) |
| Amaq Finder (v1.0, v1.7) | Tool | — | Legacy reconnaissance tool (2017) |

---

## Key Technical Capabilities

### Tornado v51 (Latest — Dec 2025)
- **Dual DGA**: Manual (base32 + custom alphabet) and blockchain-based (Bitcoin OP_RETURN data)
- **Dual C2**: HTTP and Telegram bot API
- **Infection Vector**: WinRAR exploit (CVE-2025-8088 / CVE-2025-6218) → SFX drops to startup folder
- **Second Phase**: Downloads Tonnerre with password `Hcudhl3hcbgQdpnr3`
- **RSA Verification**: 256-byte RSA signature per exfiltrated file to prevent researcher impersonation
- **Anti-Forensics**: Victim IP replaced with `0.0.0.0`, communication logs deleted, GUID-based targeting

### Blockchain C2 Resolution
- Connects to `blockchain.info/rawaddr/1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1`
- Extracts domain from `OP_RETURN OP_PUSHBYTES` values
- Deobfuscates using custom alphabet to produce C2 domain
- Provides infrastructure resilience without malware version updates

### Counter-Intelligence
- Detected SafeBreach Part I publication within 24 hours
- Replaced all C2 servers and Telegram users within 3 days
- Attempted strike-back infection against researchers via malicious ZIP in Telegram
- Added RSA signature verification to prevent researcher masquerading

---

## Iran Internet Blackout Correlation (Jan 2026)

| Date | Event |
|------|-------|
| 2026-01-08 | Iran internet blackout begins; Prince of Persia goes dormant |
| 2026-01-25 | Threat actor registers new DGA domains (2 days before blackout ends) |
| 2026-01-26 | First Foudre victim exfiltration resumes |
| 2026-01-27 | Iran internet blackout ends — SafeBreach prediction confirmed |

This timeline provides strong evidence of Iranian state sponsorship.

---

## Campaigns Tracked

| Campaign | Period | Tooling | Source |
|----------|--------|---------|--------|
| [Tornado v51](Campaigns/2025-12_Tornado/) | Dec 2025 – Feb 2026 | Tornado, Foudre, Tonnerre, ZZ Stealer, StormKitty | SafeBreach |

---

## Possible Links to Other Iranian Groups

| Group | Evidence | Strength |
|-------|----------|----------|
| Educated Manticore | ZIP/LNK + PowerShell loader technique, same attack vector pattern | Medium |
| APT33 | Remcos downloaded from same IP (191.101.130.244), VBS dropper similarity | Weak |
| Checkmarx Python Libs Attacker (2024) | Identical counter-strike technique, same ZZ Stealer variant, same PHP filenames | Strong |

---

## References

| Source | URL | Date |
|--------|-----|------|
| SafeBreach | [Prince of Persia Part II](https://www.safebreach.com/blog/prince-of-persia-part-ii/) | 2026-02-04 |
| SafeBreach | [Prince of Persia Part I](https://www.safebreach.com/blog/prince-of-persia/) | 2025-12-18 |
