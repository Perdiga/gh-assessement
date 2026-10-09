---
id: COST-127
title: "COST-127: AI usage is attributable where applicable"
sidebar_label: "COST-127"
sidebar_position: 2
---

# COST-127: AI usage is attributable where applicable

**Catalog version:** 1.1.2  
**Domain:** Cost & AI Governance  
**Severity:** medium  
**Maturity stage:** Start  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: ai usage is attributable where applicable.

## Requirement

AI usage is attributable where applicable.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `AI usage report`
  - **Fields:** `user,org,cost_center`
  - **Evidence key:** `cost.ai_attribution`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `user,org,cost_center` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: AI usage is attributable where applicable. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
