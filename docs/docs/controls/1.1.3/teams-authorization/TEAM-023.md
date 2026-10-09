---
id: TEAM-023
title: "TEAM-023: Teams have documented ownership"
sidebar_label: "TEAM-023"
sidebar_position: 5
---

# TEAM-023: Teams have documented ownership

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: teams have documented ownership.

## Requirement

Teams have documented ownership.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `Manual evidence`
  - **Fields:** `owner,description`
  - **Evidence key:** `teams.ownership`

## Evaluation logic

**Mode:** `manual_or_hybrid`

Evaluate collected evidence for `owner,description` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Teams have documented ownership. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
