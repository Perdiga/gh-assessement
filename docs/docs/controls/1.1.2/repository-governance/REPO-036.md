---
id: REPO-036
title: "REPO-036: Fork policy is appropriate"
sidebar_label: "REPO-036"
sidebar_position: 10
---

# REPO-036: Fork policy is appropriate

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: fork policy is appropriate.

## Requirement

Fork policy is appropriate.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;`
  - **Fields:** `allow_forking`
  - **Evidence key:** `repo.forks`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `allow_forking` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="REPO-036":
    return "INFO",f"repositories_allowing_forks={sum(1 for r in active if r.get('allow_forking'))}/{len(active)}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Fork policy is appropriate. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
