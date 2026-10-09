---
id: TEAM-020
title: "TEAM-020: Direct admin grants are minimized"
sidebar_label: "TEAM-020"
sidebar_position: 2
---

# TEAM-020: Direct admin grants are minimized

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** high  
**Maturity stage:** Mature  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: direct admin grants are minimized.

## Requirement

Direct admin grants are minimized.

## Risk

Significant governance, security or operational exposure.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;/collaborators`
  - **Fields:** `permissions`
  - **Evidence key:** `repo.collaborators`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `permissions` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Direct admin grants are minimized. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
