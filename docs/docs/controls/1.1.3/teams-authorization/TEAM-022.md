---
id: TEAM-022
title: "TEAM-022: Nested team structure is intentional"
sidebar_label: "TEAM-022"
sidebar_position: 4
---

# TEAM-022: Nested team structure is intentional

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: nested team structure is intentional.

## Requirement

Nested team structure is intentional.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/team/&#123;team_slug&#125;/teams`
  - **Fields:** `slug`
  - **Evidence key:** `teams.hierarchy`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `slug` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Nested team structure is intentional. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
