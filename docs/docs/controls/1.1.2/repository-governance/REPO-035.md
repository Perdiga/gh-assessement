---
id: REPO-035
title: "REPO-035: Repository naming conventions are followed"
sidebar_label: "REPO-035"
sidebar_position: 9
---

# REPO-035: Repository naming conventions are followed

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repository naming conventions are followed.

## Requirement

Repository naming conventions are followed.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/repos`
  - **Fields:** `name`
  - **Evidence key:** `repo.naming`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `name` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository naming conventions are followed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
