---
id: TEAM-021
title: "TEAM-021: Team maintainers are limited"
sidebar_label: "TEAM-021"
sidebar_position: 3
---

# TEAM-021: Team maintainers are limited

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: team maintainers are limited.

## Requirement

Team maintainers are limited.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/teams/&#123;team_slug&#125;/members`
  - **Fields:** `role`
  - **Evidence key:** `teams.maintainers`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `role` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Team maintainers are limited. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
