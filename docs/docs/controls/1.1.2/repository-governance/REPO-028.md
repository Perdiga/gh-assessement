---
id: REPO-028
title: "REPO-028: Repository visibility is appropriate"
sidebar_label: "REPO-028"
sidebar_position: 2
---

# REPO-028: Repository visibility is appropriate

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** high  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repository visibility is appropriate.

## Requirement

Repository visibility is appropriate.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;`
  - **Fields:** `visibility`
  - **Evidence key:** `repo.visibility`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `visibility` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository visibility is appropriate. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
