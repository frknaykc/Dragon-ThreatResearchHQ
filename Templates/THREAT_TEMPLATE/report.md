# [Threat Name] — Threat Analysis Report

| Field | Detail |
|-------|--------|
| **Threat Name** | [Name] |
| **Type** | [RAT / Stealer / Backdoor / Loader] |
| **Language/Platform** | [Go / C++ / C#] based, [Windows / Linux / Multi] |
| **First Detection** | [Source] |
| **Static Detection** | [X/N] detections on VirusTotal |
| **C2 Protocol** | [WebSocket / HTTPS / DNS / TCP] |
| **Report Date** | YYYY-MM-DD |

### References

| Source | Link |
|--------|------|
| **Sample** | [link](https://...) |
| **Blog Post** | [link](https://...) |
| **Original Research** | [Source Name] |

---

## 1. Executive Summary

Brief overview of the threat, its capabilities, and why it matters.

---

## 2. Attack Chain

### Phase 1 — Initial Access

Description of how the threat gains initial access.

### Phase 2 — Execution

Description of execution methods.

### Phase 3 — Command and Control

| Command | Function |
|---------|----------|
| `example_cmd` | What it does |

### Phase 4 — Actions on Objectives

Description of data theft, exfiltration, etc.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique | Command/Behavior |
|--------|-----------|------------------|
| **Execution** | T1059 - Command and Scripting Interpreter | `cmd` |

---

## 4. Indicators of Compromise (IOCs)

See [iocs.csv](iocs.csv) and [iocs.stix.json](iocs.stix.json) for full IOC sets.

### C2 Infrastructure

| Type | Value |
|------|-------|
| IPv4 | `x.x.x.x` |
| Domain | `example.com` |

### File Hashes (SHA-256)

| # | SHA-256 |
|---|---------|
| 1 | `hash` |

---

## 5. Detection and Hunting Recommendations

### Network-Based

- Detection guidance for network traffic.

### Endpoint-Based

- Detection guidance for endpoint telemetry.

### Hunting Queries

See [fingerprints.txt](fingerprints.txt) for platform-specific queries.

---

## 6. Key Findings and Conclusion

| Finding | Impact |
|---------|--------|
| Finding 1 | Impact description |

**Conclusion:** Summary assessment.
