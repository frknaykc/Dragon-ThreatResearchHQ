# Campaign — Silver Dragon: Southeast Asia & Europe

![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-white)
![Status](https://img.shields.io/badge/Status-Active-red)
![Origin](https://img.shields.io/badge/Origin-China%2FAPT41-red)

| Field | Value |
|-------|-------|
| **Campaign** | Silver Dragon — Government Targeting in SE Asia & Europe |
| **Threat Actor** | Silver Dragon (APT41 umbrella) |
| **Period** | Mid-2024 – March 2026 (ongoing) |
| **Targets** | Government entities — Southeast Asia, Europe; Uzbekistan (phishing) |
| **Initial Access** | Server exploitation + spearphishing LNK |
| **Final Payload** | Cobalt Strike (DNS tunneling + HTTP + SMB) |
| **Custom Tools** | GearDoor, SilverScreen, SSHcmd, BamboLoader, MonikerLoader |
| **Source** | [Check Point Research — Mar 2026](https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/) |

---

## Attack Chains

### Chain 1 — AppDomain Hijacking
```
RAR archive (post-exploitation delivery)
└── install.bat
    ├── Copies dfsvc.exe.config → C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
    ├── Copies ServiceMoniker.dll (MonikerLoader) → same dir
    ├── Copies ComponentModel.dll (stage-2 loader) → same dir
    ├── Copies backup.sdb (encrypted CS shellcode) → C:\Windows\AppPatch\
    └── sc delete DfSvc → sc create DfSvc → sc start DfSvc
        └── dfsvc.exe loads → MonikerLoader (AppDomain hijack)
            └── ADD-XOR decrypt ComponentModel.dll → reflective load stage-2
                └── RWE alloc → decrypt backup.sdb → execute Cobalt Strike beacon
```

### Chain 2 — Service DLL (BamboLoader)
```
RAR archive (post-exploitation delivery)
└── install.bat
    ├── Copies BamboLoader.dll → C:\Windows\System32\wbem\WinSync.dll
    ├── Copies OLDENGL.fon (encrypted CS payload) → C:\Windows\Fonts\
    └── Hijacks Windows service (e.g. bthsrv) → svchost.exe loads BamboLoader
        └── Read OLDENGL.fon → RC4 decrypt (key: rOPdyiwITK) → LZNT1 decompress
            └── CreateProcess taskhostw.exe → inject shellcode → Cobalt Strike beacon
```

### Chain 3 — Phishing LNK (Uzbekistan)
```
Phishing email → LNK attachment (>1MB, embeds all payloads)
└── cmd.exe /c PowerShell ...
    ├── Extract bytes [4184..663602]    → decoy PDF (government letter lure)
    ├── Extract bytes [663603..823554]  → GameHook.exe (legitimate, DLL sideload)
    ├── Extract bytes [823555..1032962] → graphics-hook-filter64.dll (BamboLoader)
    └── Extract bytes [1032963..1413554]→ simhei.dat (encrypted CS payload)
        └── GameHook.exe sideloads BamboLoader → Cobalt Strike beacon
```

---

## Tools Detail

### GearDoor
- **Type:** .NET backdoor
- **C2:** Google Drive (file-based, unique machine folder)
- **Encryption:** DES (key from MD5[:8] of hardcoded string)
- **Machine ID:** SHA-256(hostname) → GUID format
- **Heartbeat:** `.png` file — MachineGUID|Hostname|Username|IP|OS|Drives|Sleep|PID
- **Registry fallback:** `HKLM\Software\Microsoft\{Account,Time,Path}`
- **Self-update:** `.rar` named `wiatrace.bak` triggers version check + restart

| Extension | Direction | Operation |
|-----------|-----------|-----------|
| .png | Beacon → Drive | Heartbeat |
| .cab | Drive → Beacon | Command execution |
| .pdf | Drive → Beacon | File management |
| .rar | Drive → Beacon | File delivery / self-update |
| .7z | Drive → Beacon | Plugin (execute-assembly) |
| .db / .bak | Beacon → Drive | Command output |

### BamboLoader
- x64 C++ DLL; control flow flattening + junk code
- Reads shellcode from disk → RC4 decrypt → LZNT1 via `RtlDecompressBuffer`
- Injects into configurable target process (default: `taskhostw.exe`)
- Automated payload generator framework (all archive files share same creation timestamp)

### MonikerLoader
- .NET; Brainfuck-based string obfuscation
- Loads `ComponentModel.dll` → ADD-XOR decrypt → reflective load
- Older variants: encrypted data stored in `HKLM\Software\Microsoft\Windows`

### SilverScreen
- .NET; AppDomain hijacking (`ComponentModel.dll` naming)
- Relaunches self under active user session via token impersonation if SYSTEM
- Change-detection: grayscale thumbnail comparison → full screenshot only on change
- Output: JPEG → GZIP → local structured data file

### SSHcmd
- .NET; Renci.SshNet library
- Modes: direct command, interactive TTY, upload, download
- Supports Base64-encoded commands

---

## Cobalt Strike Beacon Config

```
BeaconType    : Hybrid HTTP DNS
SleepTime     : 99000ms (99s)
Jitter        : 51%
MaxDNS        : 252
C2 DNS        : ns1.onedriveconsole[.]com, ns2.onedriveconsole[.]com, ns1.exchange4study[.]com
C2 URI        : /d/msdownload/update/2021/11/33002773_x86_b78cd82ceba723.cab
DNS_Idle      : 104.21.51.8
Spawnto_x86   : %windir%\syswow64\dllhost.exe
Spawnto_x64   : %windir%\sysnative\dllhost.exe
PublicKey_MD5 : 9d3f61dcaba90db2ede1c1906a80ace2
Watermark     : Cracked version (common APT41 pattern)
```

---

## IOCs

Full list: [../../iocs.csv](../../iocs.csv)

| Type | Count |
|------|------:|
| C2 Domains | 13 |
| GearDoor hashes | 2 |
| SilverScreen hashes | 2 |
| SSHcmd hash | 1 |
| Phishing LNK hashes | 3 |
| BamboLoader hashes | 9 |
| MonikerLoader hashes | 4 |
| MonikerLoader stage-2 hashes | 4 |
| Install BAT hashes | 6 |
| **Total** | **44** |
