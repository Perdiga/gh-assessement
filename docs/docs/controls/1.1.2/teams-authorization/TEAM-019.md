---
id: TEAM-019
title: "TEAM-019: Repository access is primarily team-based"
sidebar_label: "TEAM-019"
sidebar_position: 1
---

# TEAM-019: Repository access is primarily team-based

**Catalog version:** 1.1.2  
**Domain:** Teams & Authorization  
**Severity:** medium  
**Maturity stage:** Start  
**Well-Architected mapping:** Observability, Simplicity

## Objective

Establish and verify the organizational practice: repository access is primarily team-based.

## Requirement

Repository access is primarily team-based.

## Risk

Meaningful control weakness requiring planned remediation.

## Evidence sources

- **Source:** `GET /orgs/&#123;org&#125;/teams/&#123;team_slug&#125;/repos`
  - **Fields:** `permissions`
  - **Evidence key:** `teams.repo_access`

## Evaluation logic

**Mode:** `automated`

Evaluate collected evidence for `permissions` against the stated requirement; distinguish missing evidence from a failing control.

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="TEAM-019":
    x=ev.get("team_repository_evidence",{})
    if not x:return "NOT ASSESSED","Team repository permission evidence unavailable."
    direct_admins=0
    total_team_repo=0
    for d in x.values():
        for repo in d.get("data",{}).get("items",[]) if isinstance(d.get("data"),dict) else []:
            total_team_repo+=1
    return ("PASS" if total_team_repo else "PARTIAL"),f"team-repository assignments observed={total_team_repo}"
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Repository access is primarily team-based. Assign an accountable owner and target date.

## Maturity-stage basis

Foundational practice aligned to the GitHub Well-Architected Start stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
