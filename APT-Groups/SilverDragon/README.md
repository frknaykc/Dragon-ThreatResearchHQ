# Threat Actor Profile — Silver Dragon

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Active](https://img.shields.io/badge/Status-Active-red)
![Origin](https://img.shields.io/badge/Origin-China-red)
![Type](https://img.shields.io/badge/Type-APT-darkred)

**Aliases:** Silver Dragon  
**Umbrella:** APT41 (Chinese-nexus, high confidence)  
**Sponsor:** China (assessed)  
**First Seen:** Mid-2024  
**Latest Activity:** March 2026  
**Source:** [Check Point Research — March 2026](https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/)

---

## Geography / Operational Focus

- Southeast Asia (primary — government entities)
- Europe (secondary — government entities)
- Uzbekistan (phishing campaign)

---

## Top Industries Targeted

- Government / Public Sector
- State-owned enterprises
- Diplomatic entities

---

## Motivation(s)

- Cyberespionage
- Intelligence collection
- Long-term persistence in government networks

---

## Toolset

### Custom Malware

| Tool | Type | Language | Notes |
|------|------|----------|-------|
| GearDoor | Backdoor | .NET | Google Drive as C2 channel; DES encryption; Brainfuck string obfuscation |
| SilverScreen | Screen Monitor | .NET | Covert screenshot capture with change-detection; JPEG+GZIP; AppDomain hijacking |
| SSHcmd | Utility | .NET | SSH wrapper — remote execution & file transfer (Renci.SshNet); Base64 command support |
| BamboLoader | Shellcode Loader | C++ x64 | RC4 + LZNT1 decompression; control flow flattening; process injection (taskhost.exe) |
| MonikerLoader | .NET Loader | .NET | Brainfuck string obfuscation; ADD-XOR decrypt; reflective load; AppDomain hijacking |

### C2 Frameworks

| Tool | Notes |
|------|-------|
| Cobalt Strike | Final payload in all observed chains; DNS tunneling + HTTP; SMB for lateral movement; cracked watermarks |

---

## Infection Chains

### 1. AppDomain Hijacking
RAR archive → batch script → `dfsvc.exe.config` overwrites AppDomain → **MonikerLoader** (`ServiceMoniker.dll`) → stage-2 loader → Cobalt Strike shellcode (`.sdb`)  
Copies to `C:\Windows\Microsoft.NET\Framework64\v4.0.30319` + `C:\Windows\AppPatch`  
Also abuses: `tzsync.exe`

### 2. Service DLL (BamboLoader)
RAR archive → batch script → **BamboLoader** DLL → registered as hijacked Windows service → RC4+LZNT1 decrypt → inject into `taskhostw.exe` → Cobalt Strike  
DLL path: `C:\Windows\System32\wbem\` | Payload: `C:\Windows\Fonts\`

**Hijacked Services:**

| Service | Masquerades As |
|---------|----------------|
| wuausrv | Windows Update Service |
| bthsrv | Bluetooth Update Service |
| COMSysAppSrv | COM+ System Application Service |
| DfSvc | .NET ClickOnce Deployment Service |
| tzsync | Timezone Synchronization Service |

### 3. Phishing (LNK)
Weaponized LNK (>1 MB) → `cmd.exe` → PowerShell extracts byte slices → drops decoy PDF + `GameHook.exe` + `graphics-hook-filter64.dll` (BamboLoader) + `simhei.dat` (CS payload)  
Target: Uzbekistan government entities

---

## Post-Exploitation Flow

```
Initial Access (exploit / phishing)
│
├── Cobalt Strike Beacon (DNS tunneling primary, HTTP secondary, SMB lateral)
│   └── C2: ns1.onedriveconsole[.]com, ns2.onedriveconsole[.]com, ns1.exchange4study[.]com
│
├── GearDoor (Google Drive C2)
│   ├── .png  → Heartbeat (machine info, IP, OS, drive listing)
│   ├── .cab  → Command execution (whoami, ps, shell, run, exec, steal_token)
│   ├── .pdf  → File management (dir, mkdir, rm)
│   ├── .rar  → File delivery / self-update
│   └── .7z   → Plugin (execute-assembly) execution
│
├── SilverScreen → Periodic screenshots → JPEG+GZIP → local file for exfil
└── SSHcmd → Remote execution / file transfer over SSH
```

---

## Attribution

High-confidence Chinese-nexus, assessed APT41 umbrella:

1. **Batch script tradecraft** — near-identical service installation script pattern to APT41 (Mandiant 2020)
2. **Cobalt Strike watermarks** — same cracked-version watermarks as previously attributed APT41 samples
3. **DNS tunneling C2** — shared TTP with APT41 campaigns
4. **RC4 + LZNT1 / RtlDecompressBuffer** — well-established Chinese-nexus shellcode loader pattern
5. **Compilation timestamps** — consistently UTC+8 (China Standard Time)

---

## Cobalt Strike Beacon Config (observed)

```
BeaconType    : Hybrid HTTP DNS
SleepTime     : 99000
Jitter        : 51
C2Server      : ns1.onedriveconsole[.]com, ns2.onedriveconsole[.]com, ns1.exchange4study[.]com
URI           : /d/msdownload/update/2021/11/33002773_x86_b78cd82ceba723.cab
DNS_Idle      : 104.21.51.8
Spawnto_x86   : %windir%\syswow64\dllhost.exe
Spawnto_x64   : %windir%\sysnative\dllhost.exe
PublicKey_MD5 : 9d3f61dcaba90db2ede1c1906a80ace2
```

---

## Campaigns Tracked

| Campaign | Period | Tools | Targets | Source |
|----------|--------|-------|---------|--------|
| [Southeast Asia & Europe](Campaigns/2026-03_SoutheastAsia-Europe/) | Mid-2024 – Mar 2026 | BamboLoader, MonikerLoader, GearDoor, SilverScreen, SSHcmd, Cobalt Strike | SEA + Europe (Gov), Uzbekistan | Check Point Research |

---

## References

| Source | URL | Date |
|--------|-----|------|
| Check Point Research | [Silver Dragon Targets Organizations in SE Asia and Europe](https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/) | 2026-03-03 |
| Mandiant (APT41 reference) | APT41 post-exploitation scripts | 2020 |
| ACN Italy (ToolShell overlap) | AppDomain hijacking chain | 2025-07 |
