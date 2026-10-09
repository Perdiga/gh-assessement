---
id: PROD-111
title: "PROD-111: Standard workflows are available"
sidebar_label: "PROD-111"
sidebar_position: 2
---

# PROD-111: Standard workflows are available

**Catalog version:** 1.1.3  
**Domain:** Developer Productivity  
**Severity:** medium  
**Maturity stage:** Start  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: standard workflows are available.

## Requirement

Standard workflows are available.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Workflow inventory`
  - **Fields:** `template,source`
  - **Evidence key:** `prod.standard_workflows`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `template,source` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Standard workflows are available. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
