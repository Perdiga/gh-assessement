---
id: REPO-030
title: "REPO-030: Internal repositories are used where appropriate"
sidebar_label: "REPO-030"
sidebar_position: 4
---

# REPO-030: Internal repositories are used where appropriate

**Catalog version:** 1.1.3  
**Domain:** Repository Governance  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: internal repositories are used where appropriate.

## Requirement

Internal repositories are used where appropriate.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/repos`
  - **Fields:** `visibility`
  - **Evidence key:** `repo.internal_use`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `visibility` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="REPO-030":
    internal=sum(1 for r in active if r.get("visibility")=="internal")
    return "INFO",f"internal_repositories={internal}/{len(active)}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Internal repositories are used where appropriate. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
