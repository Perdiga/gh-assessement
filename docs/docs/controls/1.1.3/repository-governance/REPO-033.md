---
id: REPO-033
title: "REPO-033: Archived repositories are read-only"
sidebar_label: "REPO-033"
sidebar_position: 7
---

# REPO-033: Archived repositories are read-only

**Catalog version:** 1.1.3  
**Domain:** Repository Governance  
**Severity:** low  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: archived repositories are read-only.

## Requirement

Archived repositories are read-only.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;`
  - **Fields:** `archived`
  - **Evidence key:** `repo.archived`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `archived` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="REPO-033":
    archived=[r for r in repos if r.get("archived")]
    return ("PASS" if all(r.get("archived") for r in archived) else "PARTIAL"),f"archived_repositories={len(archived)}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Archived repositories are read-only. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
