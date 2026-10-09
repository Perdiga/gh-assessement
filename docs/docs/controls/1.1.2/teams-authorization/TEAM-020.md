---
id: TEAM-020
title: "TEAM-020: Direct admin grants are minimized"
sidebar_label: "TEAM-020"
sidebar_position: 2
---

# TEAM-020: Direct admin grants are minimized

**Catalog version:** 1.1.2  
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

### Example evaluation

This is the corresponding branch from the assessment engine; shared helpers resolve the collected evidence and aggregate repository results.

```python
if cid=="TEAM-020":
    x=ev.get("repository_collaborator_evidence",{})
    if not x:return "NOT ASSESSED","Direct collaborator evidence unavailable."
    admins=0
    malformed=0
    for d in x.values():
        # Paginated/list endpoints may be stored either as the raw list
        # or in the collector envelope: {"status": 200, "data": [...]}
        data = d.get("data") if isinstance(d, dict) else d
        if isinstance(data, list):
            items=data
        elif isinstance(data, dict):
            items=data.get("items",[])
        else:
            malformed += 1
            items=[]
        if not isinstance(items, list):
            malformed += 1
            continue
        admins += sum(1 for u in items if isinstance(u, dict) and u.get("permissions",{}).get("admin"))
    reason=f"direct repository admin grants observed={admins}"
    if malformed:
        reason += f"; malformed collaborator evidence entries={malformed}"
    return ("PASS" if admins==0 else "PARTIAL"),reason
```

## Expected result

PASS when the requirement is demonstrably satisfied; PARTIAL when implementation is incomplete; FAIL when materially absent; NOT ASSESSED when evidence is unavailable; N/A only with documented rationale.

## Exception criteria

A documented, approved exception with owner, rationale, compensating control and expiry.

## Remediation guidance

Remediate the identified gap for: Direct admin grants are minimized. Assign an accountable owner and target date.

## Maturity-stage basis

Organizationally established, standardized or governed practice aligned to the GitHub Well-Architected Mature stage.

[Back to catalog version 1.1.2](/controls/1.1.2)
