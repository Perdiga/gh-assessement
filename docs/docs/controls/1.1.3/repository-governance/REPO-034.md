---
id: REPO-034
title: "REPO-034: Template repositories are governed"
sidebar_label: "REPO-034"
sidebar_position: 8
---

# REPO-034: Template repositories are governed

**Catalog version:** 1.1.3  
**Domain:** Repository Governance  
**Severity:** medium  
**Maturity stage:** Mature  
**Well-Architected mapping:** Resiliency, Simplicity, Observability

## Objective

Establish and verify the organizational practice: template repositories are governed.

## Requirement

Template repositories are governed.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /repos/&#123;owner&#125;/&#123;repo&#125;/template`
  - **Fields:** `is_template`
  - **Evidence key:** `repo.templates`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `is_template` against the stated requirement; distinguish missing evidence from a failing control.

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Template repositories are governed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
