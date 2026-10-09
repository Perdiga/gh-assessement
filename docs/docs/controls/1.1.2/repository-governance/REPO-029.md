---
id: REPO-029
title: "REPO-029: Public repositories have explicit approval"
sidebar_label: "REPO-029"
sidebar_position: 3
---

# REPO-029: Public repositories have explicit approval

**Catalog version:** 1.1.2  
**Domain:** Repository Governance  
**Severity:** high  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: public repositories have explicit approval.

## Requirement

Public repositories have explicit approval.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `Manual evidence`
  - **Fields:** `approval`
  - **Evidence key:** `repo.public_approval`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `approval` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Public repositories have explicit approval. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
