---
id: TEAM-024
title: "TEAM-024: Empty teams are reviewed"
sidebar_label: "TEAM-024"
sidebar_position: 6
---

# TEAM-024: Empty teams are reviewed

**Catalog version:** 1.1.3  
**Domain:** Teams & Authorization  
**Severity:** low  
**Maturity stage:** Mature  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: empty teams are reviewed.

## Requirement

Empty teams are reviewed.

## Risk

Hygiene or optimization opportunity.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/teams`
  - **Fields:** `members_count,repos_count`
  - **Evidence key:** `teams.empty`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `members_count,repos_count` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="TEAM-024":
    if not org_evidence_available("teams"):
        return "NOT ASSESSED",f"teams_http_status={ev.get('teams',{}).get('status')}"
    empty=sum(1 for t in teams if t.get("members_count",0)==0)
    return ("PASS" if empty==0 else "PARTIAL"),f"empty_teams={empty}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Empty teams are reviewed. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.3](/controls/1.1.3)
