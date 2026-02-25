# Contributing to Dragon Threat Research HQ

Thank you for contributing! This guide ensures consistency across the repository.

---

## Adding a New Threat

### 1. Copy the Template

```bash
cp -r Templates/THREAT_TEMPLATE/ <target-path>/ThreatName/
```

**Where to place it:**

| Threat Type | Path |
|-------------|------|
| APT Group | `APT-Groups/GroupName/` |
| RAT | `Malware/RATs/MalwareName/` |
| Stealer / Keylogger | `Malware/Stealers/MalwareName/` |
| Backdoor | `Malware/Backdoors/MalwareName/` |
| Loader / Dropper | `Malware/Loaders/MalwareName/` |
| C2 Framework | `C2-Frameworks/FrameworkName/` |
| Standalone Campaign | `Campaigns/YYYY-MM_CampaignName/` |

### 2. Fill in the Files

**Required (minimum):**

| File | What to Fill |
|------|-------------|
| `README.md` | Threat metadata table, summary, quick links |
| `iocs.csv` | At least one IOC row with all required columns |
| `iocs.stix.json` | Replace all `REPLACE-WITH-UUID` placeholders with real UUIDs |

**Recommended:**

| File | When |
|------|------|
| `report.md` | When you have a detailed analysis |
| `fingerprints.txt` | When you have Shodan/Censys/FOFA queries |
| `yara/*.yar` | When you can write detection rules |
| `screenshots/*.png` | When you have panel/sandbox/phishing screenshots |

### 3. Update the Main README

Add a row to the appropriate index table in the root `README.md`.

---

## File Naming Conventions

| Rule | Example |
|------|---------|
| No spaces in file/folder names | `APT29-CozyBear/` not `APT 29/` |
| Use hyphens for multi-word names | `Moonrise-RAT/` or `MoonriseRAT/` |
| Lowercase for standard files | `iocs.csv`, `report.md`, `fingerprints.txt` |
| YARA files use `.yar` extension | `moonrise_rat.yar` |
| Screenshots use `.png` format | `c2_panel.png` |
| Dates in ISO 8601 format | `2026-02-25`, not `25/02/2026` |

---

## IOC CSV Format

All CSV files must use this header:

```csv
type,value,description,threat,first_seen,last_seen,confidence,source,tlp,tags
```

See [Templates/IOC_CSV_HEADER.md](Templates/IOC_CSV_HEADER.md) for column definitions.

**Required columns:** `type`, `value`, `description`, `threat`, `confidence`, `tlp`

---

## STIX 2.1 Guidelines

- Every STIX bundle should contain at minimum: `malware` + `indicator` + `relationship`
- When an actor is known, include: `threat-actor` + `campaign` + full relationship chain
- Use `python3 -c "import uuid; print(uuid.uuid4())"` to generate UUIDs
- All timestamps in ISO 8601 UTC format

### Relationship Types Reference

| Source → Target | Type |
|----------------|------|
| `threat-actor` → `malware` | `uses` |
| `campaign` → `threat-actor` | `attributed-to` |
| `campaign` → `malware` | `uses` |
| `malware` → `attack-pattern` | `uses` |
| `malware` → `infrastructure` | `uses` |
| `indicator` → `malware` | `indicates` |
| `indicator` → `campaign` | `indicates` |

---

## APT Groups with Campaigns

If an APT group has multiple campaigns, organize them by date:

```
APT-Groups/MuddyWater/
├── README.md              ← Group profile (always present)
├── fingerprints.txt       ← Group-level hunting queries
├── yara/                  ← Group-level YARA rules
└── Campaigns/
    ├── 2024-09_Campaign/
    │   ├── iocs.csv
    │   ├── iocs.stix.json
    │   └── report.md
    └── 2025_Phoenix/
        ├── iocs.csv
        ├── iocs.stix.json
        └── report.md
```

---

## What NOT to Commit

- Malware binaries or executables (use `hashes.txt` instead)
- API keys, credentials, or tokens
- Personal or victim-identifying information
- Files larger than 50MB

---

## Questions?

Open an issue or reach out via the repository's communication channels.
