# GitHub Enterprise Assessment Framework v1.8.1

Read-only, evidence-driven assessment of a GitHub organization against the project's 132-control catalog.

## Production-ready report

The generated `report.md` is structured as an audit/management report:

1. **Summary** — purpose, assessment snapshot, score, failures and evidence coverage.
2. **Technical information** — execution date, authentication method, engine/framework/API versions and permission posture.
3. **Methodology** — explains the control/evidence/evaluation flow and links to the official GitHub Well-Architected reference material.
4. **Domain Maturity** — reports maturity for every assessment domain, based on scored control outcomes and the framework's 0–5 maturity model. Domains with less than 50% scored-control coverage are marked provisional.
5. **Findings** — every non-PASS result, ordered by impact/status.
6. **Appendix — Control Register** — all 132 controls with status, rationale and resolution action when applicable.

The 0–5 maturity scale is part of this assessment methodology. GitHub Well-Architected is used as the external architecture/reference model and mapping source; it is not presented as the author of this maturity scoring scale.

## GitHub Well-Architected references

- https://github.com/github/github-well-architected/blob/main/docs/framework-overview.md
- https://github.com/github/github-well-architected/blob/main/content/library/architecture/design-principles.md
- https://github.com/github/github-well-architected

## Authentication

GitHub App installation authentication is the preferred production mode. The collector creates a short-lived installation token and records the assessment principal and granted permissions. The assessment itself remains read-only.

Legacy `GITHUB_TOKEN` fallback remains available for development/troubleshooting.

## Runtime

Python 3.10+ is required. Install dependencies with:

```bash
pip install -r requirements.txt
```

The engine loads authentication settings from the project-root `.env` file. Configure either GitHub App credentials or the legacy `GITHUB_TOKEN` fallback there.

Run:

```bash
python main.py --org my-org --out assessment
```

By default, the engine loads `catalogs/latest/github_controls.json` from the project. Use `--catalog` to select another catalog.

Self-check:

```bash
python main.py --self-check
```


## Maturity progression

The report uses the GitHub Well-Architected **Start → Mature → Advance** progression. Every assessment control is assigned to one progression stage in the catalog. The assignment is owned by this assessment methodology and is grounded in the practices described by GitHub Well-Architected Design Principles.

A domain achieves a stage only when all controls assigned to that stage and preceding stages are PASS or N/A. PARTIAL, FAIL, and NOT ASSESSED block the stage. Numeric scores remain diagnostic and do not determine maturity.
