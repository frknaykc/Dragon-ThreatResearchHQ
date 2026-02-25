# IOC CSV Column Reference

All `iocs.csv` files in this repository follow this standard format.

## Header

```csv
type,value,description,threat,first_seen,last_seen,confidence,source,tlp,tags
```

## Column Definitions

| Column | Required | Description | Example Values |
|--------|----------|-------------|----------------|
| `type` | Yes | IOC type | `ipv4`, `ipv6`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`, `filename`, `registry`, `mutex`, `user-agent` |
| `value` | Yes | Raw IOC value (not defanged) | `193.23.199.88`, `evil.com` |
| `description` | Yes | Brief description | `C2 Server`, `Payload Hash`, `Phishing Domain` |
| `threat` | Yes | Associated threat name | `Moonrise RAT`, `MuddyWater` |
| `first_seen` | No | First observation date (ISO 8601) | `2026-02-25` |
| `last_seen` | No | Last observation date | `2026-03-01` |
| `confidence` | Yes | Confidence level | `high`, `medium`, `low` |
| `source` | No | IOC source | `ANY.RUN`, `VirusTotal`, `Shodan`, `Internal` |
| `tlp` | Yes | Traffic Light Protocol | `white`, `green`, `amber`, `red` |
| `tags` | No | Semicolon-separated tags | `c2;websocket;golang` |
