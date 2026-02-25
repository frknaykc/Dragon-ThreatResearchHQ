#!/usr/bin/env python3
"""
IOC Aggregation Script for Dragon-ThreatResearchHQ
Reads all IOC files, normalizes formats, and generates:
  - iocs_all.csv per APT/Malware/C2 group
  - feeds/all_iocs.csv (master)
  - feeds/domains.txt, feeds/ips.txt, feeds/hashes.txt (flat, SIEM-ready)
  - index.json (machine-readable threat index)
"""

import csv
import json
import os
import re
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent
STANDARD_HEADER = ["type", "value", "description", "threat_actor", "campaign", "confidence", "source", "tags"]

TYPE_MAP = {
    "ip": "ipv4", "ip_address": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6",
    "ip address": "ipv4", "server ip": "ipv4",
    "domain": "domain", "url": "url",
    "hostname": "domain",
    "sha256": "sha256", "sha-256": "sha256", "sha256 hash": "sha256",
    "file sha256": "sha256", "file": "sha256",
    "sha1": "sha1", "sha-1": "sha1",
    "md5": "md5", "file md5": "md5", "md5 hash": "md5",
    "hash": "hash",
    "cve": "cve",
    "c2": "ipv4",
    "file name": "filename", "filename": "filename",
    "backdoor": "sha256",
    "c2 domain": "domain", "c2 ip": "ipv4",
    "telegram_bot": "telegram_bot",
    "username": "username", "domain_name": "domain_name",
    "malware sample": "sha256", "malware download url": "url",
    "wallet address": "wallet", "wallet": "wallet",
    "contract address": "contract", "contract": "contract",
    "email address": "email",
}

def normalize_type(raw_type):
    raw = raw_type.strip().lower()
    return TYPE_MAP.get(raw, raw)

def defang(value):
    """Remove defanging brackets but keep value usable."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("hxxp", "http").replace("hxxps", "https")
    return v

def is_hash(value):
    v = value.strip()
    if re.match(r'^[a-fA-F0-9]{32}$', v):
        return "md5"
    if re.match(r'^[a-fA-F0-9]{40}$', v):
        return "sha1"
    if re.match(r'^[a-fA-F0-9]{64}$', v):
        return "sha256"
    return None

def is_ip(value):
    v = value.strip().split(":")[0]
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v))

def guess_type(value):
    v = value.strip()
    ht = is_hash(v)
    if ht:
        return ht
    if is_ip(v):
        return "ipv4"
    if v.startswith("http"):
        return "url"
    if v.startswith("CVE-"):
        return "cve"
    if "." in v and not " " in v and len(v) < 200:
        return "domain"
    return "unknown"

def extract_context_from_path(filepath):
    """Extract threat_actor and campaign from file path."""
    parts = filepath.relative_to(REPO_ROOT).parts
    threat_actor = ""
    campaign = ""

    if parts[0] == "APT-Groups" and len(parts) > 1:
        threat_actor = parts[1]
        if "Campaigns" in parts and len(parts) > parts.index("Campaigns") + 1:
            campaign = parts[parts.index("Campaigns") + 1]
    elif parts[0] == "Malware" and len(parts) > 2:
        threat_actor = parts[2]
    elif parts[0] == "C2-Frameworks" and len(parts) > 1:
        threat_actor = parts[1]
    elif parts[0] == "Campaigns" and len(parts) > 1:
        campaign = parts[1]

    return threat_actor, campaign

def parse_standard_format(filepath, reader, header):
    """Parse files with our standard format (type,value,description,...)"""
    rows = []
    threat_actor, campaign = extract_context_from_path(filepath)
    h_lower = [h.strip().lower() for h in header]

    type_col = next((i for i, h in enumerate(h_lower) if h in ("type",)), None)
    value_col = next((i for i, h in enumerate(h_lower) if h in ("value", "indicator", "indicators", "id", "iocs")), None)
    desc_col = next((i for i, h in enumerate(h_lower) if h in ("description", "details", "info", "comment", "notes")), None)
    conf_col = next((i for i, h in enumerate(h_lower) if h in ("confidence",)), None)
    source_col = next((i for i, h in enumerate(h_lower) if h in ("source",)), None)
    tags_col = next((i for i, h in enumerate(h_lower) if h in ("tags",)), None)

    if type_col is None and value_col is None:
        if h_lower[0] in ("indicator",) and h_lower[1] in ("type",):
            value_col, type_col = 0, 1
            desc_col = 2 if len(h_lower) > 2 else None

    for row in reader:
        if not row or all(not c.strip() for c in row):
            continue
        try:
            raw_type = row[type_col].strip() if type_col is not None and type_col < len(row) else ""
            raw_value = row[value_col].strip() if value_col is not None and value_col < len(row) else ""
        except IndexError:
            continue

        if not raw_value or raw_value.lower() in ("none", "n/a", ""):
            continue

        raw_value = defang(raw_value)

        if raw_type:
            ioc_type = normalize_type(raw_type)
        else:
            ioc_type = guess_type(raw_value)

        if ioc_type == "hash":
            detected = is_hash(raw_value)
            if detected:
                ioc_type = detected

        desc = row[desc_col].strip() if desc_col is not None and desc_col < len(row) else ""
        conf = row[conf_col].strip() if conf_col is not None and conf_col < len(row) else "high"
        source = row[source_col].strip() if source_col is not None and source_col < len(row) else ""
        tags = row[tags_col].strip() if tags_col is not None and tags_col < len(row) else ""

        desc = desc.replace('"', '').strip()

        rows.append({
            "type": ioc_type,
            "value": raw_value,
            "description": desc,
            "threat_actor": threat_actor,
            "campaign": campaign,
            "confidence": conf if conf else "high",
            "source": source,
            "tags": tags,
        })
    return rows

def parse_freetext(filepath, content):
    """Parse non-CSV IOC files (like Storm-1811, BLXStealer)."""
    rows = []
    threat_actor, campaign = extract_context_from_path(filepath)

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("=") or line.endswith(":"):
            continue

        for prefix in ("MD5:", "SHA-1:", "SHA-256:", "SHA1:", "SHA256:", "MD5 :"):
            if line.upper().startswith(prefix.upper()):
                val = line[len(prefix):].strip()
                ht = is_hash(val)
                if ht:
                    rows.append({"type": ht, "value": val, "description": "", "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
                break
        else:
            val = defang(line)
            if is_hash(val):
                rows.append({"type": is_hash(val), "value": val, "description": "", "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
            elif is_ip(val.split(":")[0]):
                rows.append({"type": "ipv4", "value": val.split(":")[0], "description": "", "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
            elif val.startswith("http"):
                rows.append({"type": "url", "value": val, "description": "", "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
            elif "." in val and not " " in val and len(val) < 100 and not val.startswith("/"):
                rows.append({"type": "domain", "value": val, "description": "", "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})

    return rows

def parse_storm1811(filepath):
    """Parse Storm-1811's non-standard format."""
    rows = []
    threat_actor, campaign = extract_context_from_path(filepath)
    content = filepath.read_text(errors="ignore")

    current_section = ""
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            current_section = line[:-1].lower()
            continue

        val = defang(line)
        if "domain" in current_section:
            rows.append({"type": "domain", "value": val, "description": current_section, "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
        elif "sha" in current_section or "hash" in current_section:
            ht = is_hash(val)
            if ht:
                rows.append({"type": ht, "value": val, "description": current_section, "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
        elif "relay" in current_section or "c2" in current_section or "beacon" in current_section:
            rows.append({"type": "domain", "value": val, "description": current_section, "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})
        elif is_ip(val):
            rows.append({"type": "ipv4", "value": val, "description": current_section, "threat_actor": threat_actor, "campaign": campaign, "confidence": "high", "source": "", "tags": ""})

    return rows

def process_file(filepath):
    """Process a single IOC file and return normalized rows."""
    fname = filepath.name.lower()

    if "template" in str(filepath).lower():
        return []

    if filepath.suffix == ".txt":
        content = filepath.read_text(errors="ignore")
        return parse_freetext(filepath, content)

    if fname == "iocs.csv" and "Storm-1811" in str(filepath):
        return parse_storm1811(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    if not content.strip():
        return []

    lines = content.strip().splitlines()
    if len(lines) < 2:
        return []

    try:
        dialect = csv.Sniffer().sniff(lines[0])
        reader = csv.reader(lines[1:], dialect)
        header = next(csv.reader([lines[0]], dialect))
    except Exception:
        reader = csv.reader(lines[1:])
        header = lines[0].split(",")

    return parse_standard_format(filepath, reader, header)

def get_group_root(filepath):
    """Get the group root directory for aggregation."""
    parts = filepath.relative_to(REPO_ROOT).parts
    if parts[0] == "APT-Groups" and len(parts) > 1:
        return REPO_ROOT / parts[0] / parts[1]
    elif parts[0] == "Malware" and len(parts) > 2:
        return REPO_ROOT / parts[0] / parts[1] / parts[2]
    elif parts[0] == "C2-Frameworks" and len(parts) > 1:
        return REPO_ROOT / parts[0] / parts[1]
    elif parts[0] == "Campaigns" and len(parts) > 1:
        return REPO_ROOT / parts[0] / parts[1]
    return None

def write_csv(filepath, rows):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=STANDARD_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def build_index(all_rows):
    """Build index.json from all collected data."""
    threats = {}
    for row in all_rows:
        ta = row["threat_actor"]
        if not ta:
            continue
        if ta not in threats:
            threats[ta] = {
                "name": ta,
                "campaigns": set(),
                "ioc_count": 0,
                "types": {},
            }
        threats[ta]["ioc_count"] += 1
        t = row["type"]
        threats[ta]["types"][t] = threats[ta]["types"].get(t, 0) + 1
        if row["campaign"]:
            threats[ta]["campaigns"].add(row["campaign"])

    index = {
        "generated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_iocs": len(all_rows),
        "total_threats": len(threats),
        "threats": []
    }

    categories = {}
    for d in sorted(REPO_ROOT.iterdir()):
        if d.is_dir() and d.name in ("APT-Groups", "Malware", "C2-Frameworks", "Campaigns"):
            for sub in sorted(d.rglob("README.md")):
                rel = sub.relative_to(REPO_ROOT)
                parts = rel.parts
                if d.name == "APT-Groups" and len(parts) >= 3:
                    name = parts[1]
                    cat = "apt_group"
                elif d.name == "Malware" and len(parts) >= 4:
                    name = parts[2]
                    cat = parts[1].lower().rstrip("s")
                elif d.name == "C2-Frameworks" and len(parts) >= 3:
                    name = parts[1]
                    cat = "c2_framework"
                elif d.name == "Campaigns" and len(parts) >= 3:
                    name = parts[1]
                    cat = "campaign"
                else:
                    continue
                if name not in categories:
                    categories[name] = cat

    for ta_name, data in sorted(threats.items()):
        entry = {
            "name": ta_name,
            "category": categories.get(ta_name, "unknown"),
            "path": "",
            "campaigns": sorted(data["campaigns"]),
            "ioc_count": data["ioc_count"],
            "ioc_breakdown": data["types"],
        }

        for cat_dir in ("APT-Groups", "Malware/RATs", "Malware/Stealers", "Malware/Loaders",
                        "Malware/Backdoors", "C2-Frameworks", "Campaigns"):
            candidate = REPO_ROOT / cat_dir / ta_name
            if candidate.exists():
                entry["path"] = str(Path(cat_dir) / ta_name)
                break

        index["threats"].append(entry)

    type_summary = {}
    for row in all_rows:
        t = row["type"]
        type_summary[t] = type_summary.get(t, 0) + 1
    index["type_summary"] = dict(sorted(type_summary.items(), key=lambda x: -x[1]))

    return index

def main():
    all_ioc_files = []
    for pattern in ("**/iocs*.csv", "**/iocs*.txt"):
        all_ioc_files.extend(REPO_ROOT.glob(pattern))

    all_ioc_files = [f for f in all_ioc_files if "Templates" not in str(f) and ".git" not in str(f) and "scripts" not in str(f)]
    all_ioc_files = sorted(set(all_ioc_files))

    print(f"Found {len(all_ioc_files)} IOC files to process")

    all_rows = []
    group_rows = {}

    for filepath in all_ioc_files:
        rows = process_file(filepath)
        print(f"  {filepath.relative_to(REPO_ROOT)}: {len(rows)} IOCs")
        all_rows.extend(rows)

        group_root = get_group_root(filepath)
        if group_root:
            if group_root not in group_rows:
                group_rows[group_root] = []
            group_rows[group_root].extend(rows)

    seen = set()
    unique_rows = []
    for row in all_rows:
        key = (row["type"], row["value"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(row)

    print(f"\nTotal IOCs: {len(all_rows)}, Unique: {len(unique_rows)}")

    for group_root, rows in group_rows.items():
        seen_group = set()
        unique_group = []
        for row in rows:
            key = (row["type"], row["value"])
            if key not in seen_group:
                seen_group.add(key)
                unique_group.append(row)

        if len(unique_group) > 0:
            outpath = group_root / "iocs_all.csv"
            write_csv(outpath, unique_group)
            print(f"  Written {outpath.relative_to(REPO_ROOT)}: {len(unique_group)} IOCs")

    feeds_dir = REPO_ROOT / "feeds"
    feeds_dir.mkdir(exist_ok=True)

    write_csv(feeds_dir / "all_iocs.csv", unique_rows)
    print(f"\nFeeds written:")
    print(f"  feeds/all_iocs.csv: {len(unique_rows)} IOCs")

    domains = sorted(set(r["value"] for r in unique_rows if r["type"] == "domain"))
    ips = sorted(set(r["value"] for r in unique_rows if r["type"] == "ipv4"))
    hashes = sorted(set(
        r["value"] for r in unique_rows
        if r["type"] in ("sha256", "sha1", "md5", "hash")
    ))
    urls = sorted(set(r["value"] for r in unique_rows if r["type"] == "url"))
    cves = sorted(set(r["value"] for r in unique_rows if r["type"] == "cve"))

    for fname, data in [("domains.txt", domains), ("ips.txt", ips), ("hashes.txt", hashes), ("urls.txt", urls), ("cves.txt", cves)]:
        if data:
            (feeds_dir / fname).write_text("\n".join(data) + "\n")
            print(f"  feeds/{fname}: {len(data)} entries")

    index = build_index(unique_rows)
    with open(REPO_ROOT / "index.json", "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    print(f"\nindex.json: {index['total_threats']} threats, {index['total_iocs']} IOCs")

    print("\nDone!")

if __name__ == "__main__":
    main()
