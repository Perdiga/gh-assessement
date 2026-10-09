---
id: COST-131
title: "COST-131: Self-hosted runner capacity is governed"
sidebar_label: "COST-131"
sidebar_position: 6
---

# COST-131: Self-hosted runner capacity is governed

**Catalog version:** 1.1.3  
**Domain:** Cost & AI Governance  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: self-hosted runner capacity is governed.

## Requirement

Self-hosted runner capacity is governed.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `Runner inventory`
  - **Fields:** `capacity,utilization`
  - **Evidence key:** `cost.runner_capacity`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `capacity,utilization` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Self-hosted runner capacity is governed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
