---
id: usage
title: Run an assessment
description: Run the assessment and interpret its outputs.
sidebar_position: 3
---

# Run an assessment

Run the engine from the `engine/` directory. Replace `YOUR_ORG` with the GitHub organization login; `my-org` in examples is not a literal default.

```bash
cd engine
python main.py --org YOUR_ORG --out ../assessment-output
```

The engine loads `catalogs/latest/github_controls.json` by default. Choose a specific catalog with `--catalog`:

```bash
python main.py --org YOUR_ORG \
  --catalog ../catalogs/1.1.2/github_controls.json \
  --out ../assessment-output
```

## Supply manual evidence

Controls that depend on policy, business process, or external systems can be supplied in JSON. Start from `engine/manual_evidence.example.json`, then pass the completed file:

```bash
python main.py --org YOUR_ORG \
  --manual-evidence manual-evidence.json \
  --out ../assessment-output
```

Each entry is keyed by `control_id` and includes a status and evidence-based reason. Do not use `PASS` without evidence that demonstrates the requirement is met. Evidence gaps remain `NOT ASSESSED`.

## Outputs

The output directory contains the assessment report and machine-readable evidence/results, including:

- `report.md` — management/audit report with maturity, findings, and the full control register.
- `findings.json` — per-control outcomes, domain summaries, and assessment metadata.
- `raw_evidence.json` — collected GitHub evidence.
- `evidence_provenance.json` — evidence sources, coverage, quality, and confidence.
- `permission_manifest.json`, `permission_audit.json`, and `authentication_manifest.json` — permission and authentication context.
- `summary.csv` — tabular control results.

The report is generated from the selected catalog version. Keep the catalog version with assessment outputs so results can be reproduced against the same control definitions.

## Useful options

```bash
python main.py --help
python main.py --self-check
```

Use `--inactive-days` to change the inactivity threshold, `--log-level` to adjust console detail, and `--manual-evidence` to include supplied evidence. Authentication can also be supplied through command-line options, but environment variables in `.env` are preferred to avoid exposing credentials in shell history.
