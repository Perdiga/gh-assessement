---
id: PROD-115
title: "PROD-115: Common automation is reusable"
sidebar_label: "PROD-115"
sidebar_position: 6
---

# PROD-115: Common automation is reusable

**Catalog version:** 1.1.3  
**Domain:** Developer Productivity  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: common automation is reusable.

## Requirement

Common automation is reusable.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Workflow inventory`
  - **Fields:** `reuse_ratio`
  - **Evidence key:** `prod.reuse`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `reuse_ratio` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Common automation is reusable. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
