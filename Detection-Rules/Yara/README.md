# Generic YARA Detection Rules

These YARA rules are **not tied to a specific threat**. They detect general suspicious patterns, techniques, or anomalies.

For threat-specific YARA rules, check the `yara/` folder inside each threat directory.

## Rules Index

| Rule | Description | Author |
|------|-------------|--------|
| [xor_hunter.yar](xor_hunter.yar) | Detects XOR-encoded payloads and suspicious XOR patterns | NaxoziwuS |
| [office_startup_anomaly.yar](office_startup_anomaly.yar) | Detects anomalous files in Office startup locations | NaxoziwuS |
