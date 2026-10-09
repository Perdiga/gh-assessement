---
id: PROD-112
title: "PROD-112: New repositories receive baseline controls"
sidebar_label: "PROD-112"
sidebar_position: 3
---

# PROD-112: New repositories receive baseline controls

**Catalog version:** 1.1.2  
**Domain:** Developer Productivity  
**Severity:** high  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: new repositories receive baseline controls.

## Requirement

New repositories receive baseline controls.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `Repository provisioning`
  - **Fields:** `rulesets,security,workflow`
  - **Evidence key:** `prod.baseline`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `rulesets,security,workflow` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: New repositories receive baseline controls. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
