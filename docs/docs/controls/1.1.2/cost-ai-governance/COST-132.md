---
id: COST-132
title: "COST-132: Repository/archive costs are reviewed"
sidebar_label: "COST-132"
sidebar_position: 7
---

# COST-132: Repository/archive costs are reviewed

**Catalog version:** 1.1.2  
**Domain:** Cost & AI Governance  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: repository/archive costs are reviewed.

## Requirement

Repository/archive costs are reviewed.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `Repository inventory`
  - **Fields:** `size,archived`
  - **Evidence key:** `cost.repository_hygiene`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `size,archived` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository/archive costs are reviewed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
