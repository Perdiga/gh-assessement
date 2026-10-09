---
id: TEAM-026
title: "TEAM-026: Sensitive repositories use dedicated access groups"
sidebar_label: "TEAM-026"
sidebar_position: 8
---

# TEAM-026: Sensitive repositories use dedicated access groups

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** high  
**Maturity stage:** Advance  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: sensitive repositories use dedicated access groups.

## Requirement

Sensitive repositories use dedicated access groups.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `Teams + repository inventory`
  - **Fields:** `team,repo,classification`
  - **Evidence key:** `teams.sensitive`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `team,repo,classification` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Sensitive repositories use dedicated access groups. Assign an accountable owner and target date.

## Maturity-stage basis

Advanced, automated, optimized, continuously measured or resilient practice aligned to the GitHub Well-Architected Advance stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
