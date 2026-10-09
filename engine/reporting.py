"""Assessment manifests and human-readable report rendering."""

import os

from assessment import ENGINE_VERSION
from evidence import permission_requirements
from github_client import AUTHENTICATION_VERSION


def build_control_permission_matrix(catalog):
    """Map every control to the minimum GitHub App permissions implied by its evidence sources."""
    rows=[]
    for control in catalog.get("controls",[]):
        sources=[x.get("source") for x in control.get("evidence",[]) if x.get("source")]
        requirements=[]
        for source in sources:
            for req in permission_requirements(source):
                if req not in requirements:
                    requirements.append(req)
        optional_direct=any(req.get("required") is False for req in requirements)
        rows.append({"control_id":control.get("control_id"),"domain":control.get("domain"),"evidence_sources":sources,"required_github_app_permissions":requirements,"permission_mapping_status":"MAPPED_OPTIONAL_DIRECT" if optional_direct and requirements else ("MAPPED" if requirements else "NO_API_PERMISSION_MAPPING")})
    return {"version":"1.0","controls":rows}

def authentication_manifest(auth_metadata, catalog):
    return {"version":AUTHENTICATION_VERSION,"principal":auth_metadata or {"type":"token"},"control_permission_matrix_summary":{"controls":len(catalog.get("controls",[])),"mapped_controls":sum(1 for c in catalog.get("controls",[]) if any(permission_requirements(x.get("source")) for x in c.get("evidence",[])))}}

def md_table(rows):
    """Render rows as a Markdown table. Returns a list of lines."""
    if not rows:
        return []

    def cell(value):
        if value is None:
            value = "—"
        value = str(value)
        value = value.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")
        return value

    normalized = [[cell(v) for v in row] for row in rows]
    width = max(len(row) for row in normalized)
    normalized = [row + ["—"] * (width - len(row)) for row in normalized]

    header = normalized[0]
    separator = ["---"] * width
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join(separator) + " |"]
    for row in normalized[1:]:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def write_markdown_report(
    args, catalog, findings, domains, scored, overall, critical_fail,
    auth_permission_audit, auth_metadata, evidence, result,
):
    # Production-ready Markdown report.
    # GitHub Well-Architected design principles use Start / Mature / Advance.
    # The stage names and source descriptions are GitHub-derived; the score
    # bands used to translate our control score into a stage are methodology-owned.
    # Maturity is achieved from the control progression, not from a numeric score.
    # Control-to-stage assignments are methodology-owned and reference GitHub's
    # Start / Mature / Advance Design Principles progression.
    STAGE_ORDER = ["Start", "Mature", "Advance"]
    STAGE_DESCRIPTIONS = {
        "Start": "Foundational practices are established.",
        "Mature": "Foundational and organizationally governed practices are established consistently.",
        "Advance": "Foundational, governed and advanced practices are established, including automation, optimization or resilience where applicable.",
    }

    controls_by_id = {c["control_id"]: c for c in catalog["controls"]}
    finding_by_id = {f["control_id"]: f for f in findings}

    def stage_satisfied(domain, stage):
        required = [c for c in catalog["controls"]
                    if c.get("domain") == domain and c.get("well_architected_stage") in STAGE_ORDER
                    and STAGE_ORDER.index(c.get("well_architected_stage")) <= STAGE_ORDER.index(stage)]
        blockers = []
        for c in required:
            f = finding_by_id.get(c["control_id"])
            status = f.get("status") if f else "NOT ASSESSED"
            if status not in ("PASS", "N/A"):
                blockers.append({"control_id": c["control_id"], "status": status, "title": c.get("title")})
        return (len(blockers) == 0, required, blockers)

    def domain_maturity(domain, score, scored, total):
        coverage=(scored/total) if total else 0
        achieved=[]
        for stage in STAGE_ORDER:
            ok, required, blockers = stage_satisfied(domain, stage)
            if ok:
                achieved.append(stage)
            else:
                break
        if achieved:
            stage=achieved[-1]
            return stage + (" (provisional)" if coverage < 0.5 else ""), STAGE_DESCRIPTIONS[stage], stage, coverage, blockers
        return "Below Start", "Foundational controls are not all satisfied.", None, coverage, stage_satisfied(domain,"Start")[2]

    maturity_rows=[]
    maturity_detail={}
    for d,v in domains.items():
        maturity,description,stage,coverage,blockers=domain_maturity(d,v["score"],v["scored"],v["total"])
        maturity_rows.append((d,maturity,f"{v['score'] if v['score'] is not None else 'N/A'}",f"{v['scored']}/{v['total']}",f"{coverage*100:.0f}%",description))
        maturity_detail[d]={"stage":stage,"display":maturity,"coverage":coverage,"blockers":blockers}

    status_order={"FAIL":0,"PARTIAL":1,"NOT ASSESSED":2,"INFO":3,"N/A":4,"PASS":5}
    findings_for_report=[f for f in findings if f["status"] != "PASS"]
    findings_for_report.sort(key=lambda f:(status_order.get(f["status"],9), {"critical":0,"high":1,"medium":2,"low":3,"informational":4}.get(f["severity"],9), f["control_id"]))

    md=[
        f"# GitHub Enterprise Assessment — {args.org}", 
        "",
        "## Summary",
        "",
        "This assessment evaluates the GitHub organization against an organization-specific control catalog aligned to the GitHub Well-Architected Framework. It combines automatically collected GitHub API evidence with policy and external evidence where the API cannot establish the requirement.",
        "",
        "The assessment is evidence-driven: **NOT ASSESSED** means that the available evidence was insufficient for a defensible conclusion; it is not treated as a pass or failure. **PASS**, **PARTIAL**, and **FAIL** are scored states, while **INFO** records an observation and **N/A** records a demonstrably non-applicable control.",
        "",
        "### Assessment snapshot",
        "",
    ]
    total_controls = len(findings)
    scored_count = len(scored)

    md += md_table([
        ("Metric","Value"),
        ("Organization",args.org),
        ("Overall score",overall if overall is not None else "N/A"),
        ("Controls",f"{total_controls}"),
        ("Passed",f"{scored_count}"),
        ("Failures",result["summary"]["failures"]),
        ("Critical failures",critical_fail),
        ("Not assessed",result["summary"]["not_assessed"]),
    ])

    md += ["","## Technical Information","",]
    md += md_table([
        ("Item","Value"),
        ("Execution date",evidence["metadata"].get("collected_at","N/A")),
        ("Authentication method",(auth_metadata or {}).get("type","token")),
        ("Engine version",ENGINE_VERSION),
        ("Controls version",catalog.get("version","N/A")),
    ])

    md += ["","## Methodology","",
        "The assessment framework is an independent control and scoring methodology that uses GitHub Well-Architected as its external architectural reference. The GitHub Well-Architected repository describes architecture design principles with a progression of **Start**, **Mature**, and **Advance** practices. The assessment catalog maps controls to relevant GitHub Well-Architected principles/dimensions.",
        "",
        "The assessment flow is: **control catalog → evidence source → read-only collection → evidence quality/provenance → control evaluation → finding status → domain score → maturity stage → remediation action**.",
        "",
        "Evidence may come from GitHub API inventory, repository configuration, organization settings, security data, Actions configuration, or explicitly supplied manual/external evidence. API unavailability, missing fields, policy-dependent requirements, and privileged endpoints are represented as evidence blockers rather than silently interpreted as control failures.",
        "",
        "### Result states",
        "",
        "- **PASS** — evidence demonstrates the requirement is met.",
        "- **PARTIAL** — the requirement exists but coverage or implementation is incomplete.",
        "- **FAIL** — evidence demonstrates a material control deficiency.",
        "- **NOT ASSESSED** — available evidence is insufficient for a defensible conclusion.",
        "- **N/A** — the control is demonstrably not applicable.",
        "- **INFO** — informational observation; not scored as a control outcome.",
        "",
        "### Maturity model",
        "",
        "GitHub Well-Architected defines a progression of **Start → Mature → Advance** within its Design Principles. The source material describes the practices expected at each stage; it does not publish this assessment catalog's exact control-to-stage mapping.",
        "",
        "This assessment therefore assigns every control to a progression stage as a **methodology-owned mapping**, using the GitHub Design Principles as the reference. The assignment is recorded in the control catalog and is intended to make the maturity model explicit and auditable.",
        "",
        "A domain reaches **Start** only when all controls assigned to Start are PASS or N/A. It reaches **Mature** only when all Start and Mature controls are PASS or N/A. It reaches **Advance** only when all Start, Mature and Advance controls are PASS or N/A. PARTIAL, FAIL and NOT ASSESSED block the corresponding stage.",
        "",
        "### GitHub Well-Architected progression",
        "",
        "**Start** establishes foundational practices and understanding of the current state. **Mature** establishes standardized, governed and repeatable practices. **Advance** emphasizes implementation at scale, automation, optimization, continuous improvement, resilience or other advanced practices depending on the Design Principle.",
        "",
        "### References",
        "",
        "- [GitHub Well-Architected Framework Overview](https://github.com/github/github-well-architected/blob/main/docs/framework-overview.md) — framework structure, pillars and relationship to GitHub guidance.",
        "- [GitHub Well-Architected Architecture Design Principles](https://github.com/github/github-well-architected/blob/main/content/library/architecture/design-principles.md) — Start, Mature and Advance progression for architecture principles.",
        "- [GitHub Well-Architected Application Security Design Principles](https://github.com/github/github-well-architected/blob/main/content/library/application-security/design-principles.md) — security maturity practices and progression.",
        "- [GitHub Well-Architected repository](https://github.com/github/github-well-architected) — source repository for the framework and content library.",
    ]

    md += ["","## Domain Maturity","",
           "Domain maturity is expressed using the GitHub Well-Architected **Start / Mature / Advance** terminology. Maturity is determined by achievement of the control stages in the catalog.","",
    ]
    md += md_table([("Domain","Stage","Scored","Coverage","Basis")]+maturity_rows)
    md += ["", "### Stage progression and blockers", "", "The following controls determine the next maturity stage. A control blocks stage achievement when its status is FAIL, PARTIAL or NOT ASSESSED.", ""]
    for d in domains:
        md += [f"#### {d}", ""]
        for stage in STAGE_ORDER:
            ok, required, blockers = stage_satisfied(d, stage)
            status = "ACHIEVED" if ok else "BLOCKED"
            md += [f"**{stage} — {status}**"]
            if blockers:
                md += ["", "| Control | Status | Requirement |", "| --- | --- | --- |"]
                for b in blockers:
                    c=controls_by_id.get(b["control_id"], {})
                    md.append(f"| {b['control_id']} | {b['status']} | {c.get('requirement','—')} |")
                md.append("")
            else:
                md += ["", "All controls through this stage are satisfied.", ""]

    md += ["","## Findings","",
           "This section contains every non-PASS result: FAIL, PARTIAL, NOT ASSESSED, INFO and N/A. The complete control inventory is included in the Appendix for auditability.","",
    ]
    md += md_table([("Control","Severity","Status","Domain","Finding / Evidence","Resolution")]+[
        (f["control_id"],f["severity"],f["status"],f["domain"],f"{f['title']} — {f['reason']}",((f.get("assessment_blocker") or {}).get("resolution") or "—"))
        for f in findings_for_report
    ])

    md += ["","## Appendix — Control Register","",
           "Complete control inventory. Resolution actions are shown whenever the control has an assessment blocker; PASS controls have no remediation action.","",
    ]
    md += md_table([("Control","Domain","Stage","Severity","Status","Resolution Action","Evidence / Rationale")]+[
        (f["control_id"],f["domain"],controls_by_id.get(f["control_id"],{}).get("well_architected_stage","—"),f["severity"],f["status"],((f.get("assessment_blocker") or {}).get("resolution") or "—"),f["reason"])
        for f in findings
    ])
    with open(os.path.join(args.out,"report.md"),"w",encoding="utf-8") as f: f.write("\n".join(md))


