---
id: COST-126
title: "COST-126: GitHub resource usage is attributable"
sidebar_label: "COST-126"
sidebar_position: 1
---

# COST-126: GitHub resource usage is attributable

**Catalog version:** 1.1.2  
**Domain:** Cost & AI Governance  
**Severity:** medium  
**Maturity stage:** Start  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: github resource usage is attributable.

## Requirement

GitHub resource usage is attributable.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Billing/usage reports`
  - **Fields:** `org,cost_center`
  - **Evidence key:** `cost.attribution`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `org,cost_center` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: GitHub resource usage is attributable. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
