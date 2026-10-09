---
id: COST-130
title: "COST-130: Actions compute usage is reviewed"
sidebar_label: "COST-130"
sidebar_position: 5
---

# COST-130: Actions compute usage is reviewed

**Catalog version:** 1.1.2  
**Domain:** Cost & AI Governance  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: actions compute usage is reviewed.

## Requirement

Actions compute usage is reviewed.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Actions billing/usage`
  - **Fields:** `minutes,runner`
  - **Evidence key:** `cost.actions_usage`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `minutes,runner` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Actions compute usage is reviewed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
