---
id: COST-129
title: "COST-129: AI credit consumption anomalies are monitored"
sidebar_label: "COST-129"
sidebar_position: 4
---

# COST-129: AI credit consumption anomalies are monitored

**Catalog version:** 1.1.3  
**Domain:** Cost & AI Governance  
**Severity:** medium  
**Maturity stage:** Advance  
**Well-Architected mapping:** Scalability, Resiliency, Efficiency, Disaster Recovery, Modularity, Interoperability, Simplicity, Observability

## Objective

Establish and verify the organizational practice: ai credit consumption anomalies are monitored.

## Requirement

AI credit consumption anomalies are monitored.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Usage reports`
  - **Fields:** `consumption,threshold`
  - **Evidence key:** `cost.ai_anomaly`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `consumption,threshold` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: AI credit consumption anomalies are monitored. Assign an accountable owner and target date.

## Maturity-stage basis

Advanced, automated, optimized, continuously measured or resilient practice aligned to the GitHub Well-Architected Advance stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
