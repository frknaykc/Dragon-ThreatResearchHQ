# Campaign — Ghost Tap: NFC Payment Relay Fraud

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Active-red)
![Platform](https://img.shields.io/badge/Platform-Android-green)

| Field | Value |
|-------|-------|
| **Campaign** | Ghost Tap — NFC-enabled payment relay fraud |
| **Threat Actors** | Chinese cybercrime ecosystem (TX-NFC, X-NFC, NFU Pay vendors) |
| **Active Since** | August 2024 |
| **Target** | Global — banking customers, payment card holders |
| **Financial Impact** | $355,000+ (single vendor, Nov 2024 – Aug 2025) |
| **IOCs** | 54 SHA256 + 54 SHA1 + 54 MD5 + 5 domains = **167 IOCs** |
| **Samples** | 54+ malicious APK variants identified |
| **Source** | [Group-IB](https://www.group-ib.com/blog/ghost-tapped-chinese-malware/) |

---

## Summary

"Ghost Tap" is a sophisticated Android malware campaign operated by Chinese threat actors that exploits NFC (Near Field Communication) technology to conduct unauthorized tap-to-pay transactions remotely. The operation involves two coordinated Android applications — a **Reader** (victim-side) and a **Tapper** (criminal-side) — that relay payment card NFC data through C2 servers, enabling fraudulent transactions as if the victim's card were physically present at a POS terminal.

Group-IB identified a structured underground economy with multiple competing vendors on Telegram, subscription-based pricing models ($45–$1,050), 24/7 customer support, and a parallel black market for illicitly acquired POS terminals.

---

## Attack Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                      GHOST TAP FLOW                         │
│                                                             │
│  VICTIM SIDE                         CRIMINAL SIDE          │
│  ──────────                          ─────────────          │
│                                                             │
│  ┌──────────────┐    WebSocket    ┌──────────────┐          │
│  │ "Reader" App │───── C2 ──────▶│ "Tapper" App │          │
│  │ (victim phone)│    Server      │ (criminal    │          │
│  └──────┬───────┘                 │   phone)     │          │
│         │                         └──────┬───────┘          │
│         │ NFC                            │ NFC Emulation    │
│         ▼                                ▼                  │
│  ┌──────────────┐                 ┌──────────────┐          │
│  │ Victim's     │                 │ POS Terminal │          │
│  │ Bank Card    │                 │ (stolen/     │          │
│  │              │                 │  illicit)    │          │
│  └──────────────┘                 └──────────────┘          │
│                                                             │
│  Card tapped → NFC data captured → relayed → fraud payment  │
└─────────────────────────────────────────────────────────────┘
```

### Step-by-Step

1. **Social Engineering** — Victims lured via smishing (SMS phishing) or vishing (voice phishing) to install malicious APK disguised as legitimate banking app
2. **Reader Installation** — Malicious "Reader" app installed on victim's Android device
3. **Card Capture** — Victim tricked into tapping bank card against phone ("verify identity" or "update payment details")
4. **NFC Relay** — Reader app sends `2PAY.SYS.DDF01` PPSE command, captures ISO 14443 contactless payment data, stores Application Identifiers (AIDs)
5. **C2 Relay** — All NFC data transmitted via **WebSocket** to attacker's C2 server
6. **Tapper Emulation** — "Tapper" app on criminal's device emulates victim's card using relayed data
7. **Cash-Out** — Criminal taps emulated card at POS terminal (often illicitly acquired) to complete payment

### Alternative Cash-Out

- Preload compromised card details into mobile wallets (Apple Pay / Google Pay clones)
- Deploy networks of mules globally to make purchases at physical retail locations

---

## Malware Vendors (Telegram)

| Vendor | Established | Subscribers | Pricing | Notes |
|--------|-------------|-------------|---------|-------|
| **TX-NFC** | Jan 2025 | 21,000+ | $45 (1 day) – $1,050 (3 months) | Largest vendor, English support, 24/7 customer service |
| **X-NFC** | Dec 2024 | 5,000+ | Similar | Second-largest marketplace |
| **NFU Pay** | — | Fewer | — | Country-specific builds (Brazil, Italy), redistributed by other vendors |
| **Oedipus** | — | — | — | POS terminal vendor (TX-NFC affiliated), terminals from ME/Africa/Asia |

---

## Technical Characteristics

| Property | Detail |
|----------|--------|
| **Platform** | Android (APK) |
| **NFC Protocol** | ISO 14443 (contactless payment) |
| **PPSE Command** | `2PAY.SYS.DDF01` (Proximity Payment System Environment) |
| **C2 Protocol** | WebSocket |
| **Packing** | 360 Jiagu (Chinese commercial packer) |
| **Code Base** | Some variants based on **NFCProxy** (open-source GitHub project) |
| **Permissions** | NFC hardware, internet, foreground service (persistence) |
| **Entry Point** | `LoginActivity` (main manifest entrypoint) |
| **Tag Support** | ISO 14443 cards + various NFC tag types |
| **Samples** | 54+ unique APKs identified (May 2024 – Dec 2025) |
| **Obfuscation** | Commercial packer + custom obfuscation |

---

## Financial Impact

| Metric | Value |
|--------|-------|
| **Single vendor (Oedipus) losses** | $355,000+ (Nov 2024 – Aug 2025) |
| **Reported victim losses (China)** | $13,000+ per case |
| **Industry warning** | Visa Payment Ecosystem Risk & Control — Spring 2025 Biannual Threats Report |

---

## Law Enforcement Actions

| Date | Location | Details |
|------|----------|---------|
| Nov 2024 | Singapore | 5 arrested — contactless payments without physical cards |
| Mar 2025 | Knoxville, Tennessee (US) | 11 Chinese nationals — gift card purchases worth tens of thousands |
| — | Czech Republic | Suspects apprehended for NFC relay fraud |
| — | Malaysia | Arrests related to NFC relay attacks |
| — | China | Law enforcement actions against domestic operators |

---

## Detection Indicators

### Behavioral Signatures
- Android app requesting NFC + internet + foreground service permissions simultaneously
- `2PAY.SYS.DDF01` PPSE initiation from non-payment applications
- WebSocket connections from NFC-handling apps to unknown servers
- ISO 14443 card interaction followed by immediate network activity
- APK packed with 360 Jiagu containing NFC-related code

### POS Terminal Anomalies
- Transactions from geographically dispersed terminals with identical card data
- Rapid successive transactions from different POS terminals using same card
- Terminals registered to suspicious entities in ME/Africa/Asia regions

---

## References

| Source | URL | Date |
|--------|-----|------|
| Group-IB | [Ghost Tapped: Chinese Malware](https://www.group-ib.com/blog/ghost-tapped-chinese-malware/) | 2026 |
| SecurityOnline | [Ghost Tap Rising](https://securityonline.info/ghost-tap-rising-new-wave-of-android-malware-turns-phones-into-digital-pickpockets/) | 2026 |
| GBHackers | [New Ghost Tap Attack](https://gbhackers.com/new-ghost-tap-attack/) | 2026 |
| Infosecurity | [Ghost Tap Malware Fuels NFC Fraud](https://www.infosecurity-magazine.com/news/ghost-tap-malware-remote-nfc-fraud/) | 2026 |
| Visa | Spring 2025 Biannual Threats Report | 2025 |

---

## Quick Links

| Resource | File |
|----------|------|
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| MITRE ATT&CK | [mitre_attack.md](mitre_attack.md) |
