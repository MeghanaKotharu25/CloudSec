# CloudSec-Copilot Demo Flow

This document describes a simple end-to-end demonstration flow for a classroom or project demo.

## 1. Environment start

```bash
cd /Users/lakshmikotaru/CLOUD
conda activate ai
docker compose up -d
```

## 2. Run discovery

```bash
python -m cloudsec_copilot.cli.main scan --discover-only --output infra_state.json
```

## 3. Run full security scan

```bash
python -m cloudsec_copilot.cli.main scan
```

## 4. Review prioritized findings

The system builds a graph and ranks findings by exposure, blast radius, and privilege level. The highest-priority items are shown first.

## 5. Fix a finding

```bash
python -m cloudsec_copilot.cli.main fix --id VULN-001 --yes
```

## 6. Verify the result

```bash
python -m cloudsec_copilot.cli.main verify
```

## 7. Export report

```bash
python -m cloudsec_copilot.cli.main report --format json --output scan_report.json
```

## Visuals used in the demo

- architecture diagram in the project README
- graph-level dependency view of EC2 -> IAM -> S3
- CLI output from the scan and verification commands
- JSON report snapshot with findings and risk ordering

These visuals are intentionally minimal and operationally realistic rather than decorative.
