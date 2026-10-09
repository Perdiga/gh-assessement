---
id: REPO-032
title: "REPO-032: Topics/classification metadata is present"
sidebar_label: "REPO-032"
sidebar_position: 6
---

# REPO-032: Topics/classification metadata is present

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: topics/classification metadata is present.

## Requirement

Topics/classification metadata is present.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;`
  - **Fields:** `topics`
  - **Evidence key:** `repo.classification`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `topics` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="REPO-032":
    return aggregate(lambda r:bool(r.get("topics")))
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Topics/classification metadata is present. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
