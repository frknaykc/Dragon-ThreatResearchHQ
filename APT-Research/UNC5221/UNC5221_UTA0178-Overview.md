# APT Group: UNC5221 / UTA0178

**Aliases:** UNC5221 (Mandiant), UTA0178 (Volexity)  
**Country of Origin:** China  
**Motivation:** Information theft and espionage  
**First Observed:** 2022  

---

## Overview
**UNC5221 / UTA0178** is a China-nexus cyber espionage group tracked by **Mandiant** and **Volexity**.  
The group is known for targeting **Ivanti Connect Secure (formerly Pulse Secure)** and **Ivanti Policy Secure** appliances using zero-day vulnerabilities to gain initial access and deploy custom malware, including **BRICKSTORM** and related components.

The operations of UNC5221 demonstrate a strong focus on **stealth, persistence, and information collection** from government, technology, legal, and managed service sectors worldwide.

---

## Campaign Summary

### Ivanti Zero-Day Exploitation
On **January 10, 2024**, Ivanti disclosed two critical vulnerabilities:
- **CVE-2023-46805** — Authentication bypass  
- **CVE-2024-21887** — Command injection  

These vulnerabilities affect **Ivanti Connect Secure (CS)** and **Ivanti Policy Secure (PS)**.  
Mandiant confirmed **zero-day exploitation as early as December 2023**, attributing the activity to **UNC5221**, a suspected Chinese espionage actor.

Successful exploitation allowed threat actors to **bypass authentication**, execute arbitrary commands, and **pivot deeper into victim networks**.

---

### BRICKSTORM Espionage Operations
In **September 2025**, Google Cloud’s Threat Intelligence team (GTIG) published a detailed analysis titled  
**“Another BRICKSTORM: Stealthy Backdoor Enabling Espionage into Tech and Legal Sectors.”**  
This campaign involved the **BRICKSTORM** backdoor, a modular and persistent implant used by UNC5221 for long-term espionage operations.

Key findings:
- Active since at least **March 2025**, targeting technology, legal, and SaaS providers.  
- Maintains **long dwell times** (average **393 days** before detection).  
- Deploys **BRICKSTORM** on edge appliances and VMware vCenter systems.  
- Uses **BRICKSTEAL**, a Java Servlet filter that captures credentials from web sessions.  
- Performs **VM cloning and offline data exfiltration** to avoid detection.  
- Utilizes **dynamic C2 infrastructure**, **DNS-over-HTTPS**, and **anti-forensic measures**.  
- Related tools include **GLASSTOKEN, LIGHTWIRE, PySoxy, THINSPOOL, WARPWIRE, WIREFIRE, ZIPLINE.**

---

## Observations
- **Global targeting** — observed worldwide.  
- **Focus sectors:** technology, government, legal, SaaS, and managed service providers.  
- **Persistence:** stealthy, appliance-based footholds without EDR visibility.  
- **Attribution:** China-linked espionage cluster with overlaps in TTPs across UNC5221 and UTA0178.  

---

## Tools & Malware
- `BRICKSTORM` — primary espionage backdoor  
- `BRICKSTEAL` — credential-stealing servlet  
- `GLASSTOKEN`, `LIGHTWIRE`, `PySoxy`, `THINSPOOL`, `WARPWIRE`, `WIREFIRE`, `ZIPLINE` — supporting modules and payloads  

---

## Key Operations Timeline
| Year | Event |
|------|-------|
| **2022** | NVISO analyzes *BRICKSTORM* espionage backdoor. |
| **Dec 2023** | Zero-day exploitation of Ivanti vulnerabilities begins. |
| **Jan 10, 2024** | Ivanti publicly discloses CVE-2023-46805 and CVE-2024-21887. |
| **Jan 2024** | Volexity reports global exploitation of Ivanti Connect Secure VPN. |
| **Mar 2025** | Google Cloud Threat Intelligence identifies new Ivanti exploit (CVE-2025-22457). |
| **Sep 2025** | GTIG publishes *“Another BRICKSTORM”* campaign report. |

---

## Security Recommendations
- Apply **Ivanti patches** for all Connect Secure / Policy Secure systems.  
- Scan for BRICKSTORM and BRICKSTEAL artifacts using **GTIG’s detection scripts**.  
- Monitor for suspicious admin actions, new user accounts, or modified servlet components.  
- Enable **EDR or logging** on appliances and VMware systems where possible.  
- Investigate outbound traffic patterns for C2 activity and DNS-over-HTTPS anomalies.  
- Treat edge devices as high-risk assets in threat-hunting and IR workflows.  

---

## References

### Primary Threat Intelligence Sources
1. **Mandiant:** [Suspected APT Targets Ivanti Zero-Day](https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day)  
2. **Volexity:** [Active Exploitation of Two Zero-Day Vulnerabilities in Ivanti Connect Secure VPN (Jan 10, 2024)](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/)  
3. **Volexity:** [Ivanti Connect Secure VPN Exploitation Goes Global (Jan 15, 2024)](https://www.volexity.com/blog/2024/01/15/ivanti-connect-secure-vpn-exploitation-goes-global/)  
4. **NVISO:** [BRICKSTORM Analysis Report (2025)](https://blog.nviso.eu/wp-content/uploads/2025/04/NVISO-BRICKSTORM-Report.pdf)  
5. **Google Cloud (Threat Intelligence):** [China-Nexus Threat Actor Exploiting Critical Ivanti Vulnerability (Mar 2025)](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability)  
6. **Google Cloud (Threat Intelligence):** [Another BRICKSTORM: Stealthy Backdoor Enabling Espionage Campaign (Sep 2025)](https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign)

