---
id: REPO-031
title: "REPO-031: Repository descriptions identify purpose"
sidebar_label: "REPO-031"
sidebar_position: 5
---

# REPO-031: Repository descriptions identify purpose

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** low  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repository descriptions identify purpose.

## Requirement

Repository descriptions identify purpose.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;`
  - **Fields:** `description`
  - **Evidence key:** `repo.description`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `description` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="REPO-031":
    return aggregate(lambda r:bool(r.get("description")))
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository descriptions identify purpose. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
