---
id: REPO-027
title: "REPO-027: Repositories have documented ownership"
sidebar_label: "REPO-027"
sidebar_position: 1
---

# REPO-027: Repositories have documented ownership

**Catalog version:** 1.1.3  
**Domain:** Repository Governance  
**Severity:** high  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repositories have documented ownership.

## Requirement

Repositories have documented ownership.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `Manual evidence / repository metadata`
  - **Fields:** `CODEOWNERS,maintainer`
  - **Evidence key:** `repo.ownership`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `CODEOWNERS,maintainer` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repositories have documented ownership. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
