---
id: PROD-110
title: "PROD-110: Repository templates are available"
sidebar_label: "PROD-110"
sidebar_position: 1
---

# PROD-110: Repository templates are available

**Catalog version:** 1.1.3  
**Domain:** Developer Productivity  
**Severity:** medium  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repository templates are available.

## Requirement

Repository templates are available.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/repos`
  - **Fields:** `is_template`
  - **Evidence key:** `prod.templates`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `is_template` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="PROD-110":
    templates=sum(1 for r in repos if r.get("is_template"))
    return ("PASS" if templates else "PARTIAL"),f"template_repositories={templates}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository templates are available. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
