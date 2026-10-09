---
id: COST-128
title: "COST-128: AI budgets are defined where applicable"
sidebar_label: "COST-128"
sidebar_position: 3
---

# COST-128: AI budgets are defined where applicable

**Catalog version:** 1.1.3  
**Domain:** Cost & AI Governance  
**Severity:** high  
**Maturity stage:** Mature  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: ai budgets are defined where applicable.

## Requirement

AI budgets are defined where applicable.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `Billing budget APIs/reports`
  - **Fields:** `scope,limit`
  - **Evidence key:** `cost.ai_budgets`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `scope,limit` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: AI budgets are defined where applicable. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
