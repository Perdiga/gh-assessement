"""Evidence quality, control evaluation, and scoring."""

import re
from datetime import datetime, timezone
from evidence import (
    file_text,
    getv,
    merged_rules,
    ok,
    organization_rulesets_from_repository_evidence,
    repo_data,
    repo_items,
    rule_types,
)


STATUSES={"PASS","PARTIAL","FAIL","N/A","NOT ASSESSED","INFO"}
SEVERITY_WEIGHT={"critical":4,"high":3,"medium":2,"low":1}
STATUS_SCORE={"PASS":1.0,"PARTIAL":0.5,"FAIL":0.0}

ASSESSMENT_BLOCKERS = {
    "PERMISSION_GAP": "Evidence source is inaccessible because the assessment principal lacks the required GitHub permission.",
    "PRIVILEGED_ENDPOINT_REQUIRED": "The evidence requires a GitHub endpoint whose documented access level is higher than the read-only assessment posture; this is an intentional least-privilege limitation, not a missing read permission.",
    "ENDPOINT_UNAVAILABLE": "Required evidence endpoint is unavailable or returned an unresolved transport/API error.",
    "FIELD_UNAVAILABLE": "Evidence endpoint is available, but one or more required fields are unavailable or null.",
    "POLICY_REQUIRED": "Evidence is available, but the control requires an organization-defined policy, convention, threshold, or governance decision.",
    "MANUAL_EVIDENCE_REQUIRED": "The control requires process, operational, identity, governance, or other evidence that must be supplied outside the collected GitHub inventory.",
    "FEATURE_NOT_ENABLED": "The relevant GitHub feature is disabled, so the feature-specific evidence cannot be evaluated.",
    "NOT_COLLECTED": "The required evidence source is known but is not collected or mapped by this release.",
}
BLOCKER_RESOLUTIONS = {
    "PRIVILEGED_ENDPOINT_REQUIRED": {
        "code": "OPTIONAL_PRIVILEGED_COLLECTION",
        "action": "Keep the assessment principal read-only, or run a separately authorized privileged evidence collection for this control; do not grant write access solely to improve the score unless the security policy explicitly permits it.",
    },
    "PERMISSION_GAP": {
        "code": "TOKEN_PERMISSION_CHANGE",
        "action": "Grant the required minimum GitHub permission to the assessment principal, then rerun the assessment.",
    },
    "ENDPOINT_UNAVAILABLE": {
        "code": "ENDPOINT_INVESTIGATION",
        "action": "Investigate endpoint availability, API behavior, or transient access failures; rerun after the source is reachable.",
    },
    "FIELD_UNAVAILABLE": {
        "code": "FIELD_ACCESS_VALIDATION",
        "action": "Validate that the required API fields are exposed to the assessment principal and supported by the selected API version.",
    },
    "POLICY_REQUIRED": {
        "code": "DEFINE_ORGANIZATIONAL_POLICY",
        "action": "Define and provide the organization-specific policy, convention, standard, threshold, or governance decision required by the control.",
    },
    "MANUAL_EVIDENCE_REQUIRED": {
        "code": "COLLECT_EXTERNAL_EVIDENCE",
        "action": "Provide the required process, operational, identity, governance, or other external evidence and attach it to the assessment.",
    },
    "FEATURE_NOT_ENABLED": {
        "code": "ENABLE_OR_DOCUMENT_FEATURE",
        "action": "Enable the relevant GitHub feature where required, or document an approved alternative/control treatment.",
    },
    "NOT_COLLECTED": {
        "code": "COLLECTOR_ENHANCEMENT",
        "action": "Extend the collector/evidence resolver to collect and map the declared evidence source, then rerun the assessment.",
    },
}

def blocker_resolution(category):
    """Return the deterministic next action for an assessment blocker."""
    return dict(BLOCKER_RESOLUTIONS.get(category, {
        "code": "INVESTIGATE",
        "action": "Investigate the unresolved evidence blocker and rerun the assessment after remediation.",
    }))


def _source_is_manual(source):
    s=(source or "").lower()
    return any(x in s for x in (
        "manual evidence", "hr or iam", "runbook", "exercise evidence",
        "architecture evidence", "policy", "register", "risk register",
        "assessment history", "control matrix", "evidence store",
        "finding tracker", "iam evidence", "idp", "enterprise membership",
        "discussion", "metrics dashboard", "secret store",
    ))

def _reason_is_manual(reason):
    s=(reason or "").lower()
    return any(x in s for x in (
        "manual evidence", "cannot be proven", "requires external",
        "requires process evidence", "requires review records",
        "requires operational documentation", "requires identity",
        "requires enterprise identity", "outside the github",
        "organizational context", "organizational evidence", "governance evidence",
        "idp/enterprise",
    ))

def _reason_is_policy(reason):
    s=(reason or "").lower()
    return any(x in s for x in (
        "organization-specific", "organization-defined", "policy",
        "policy threshold", "naming compliance", "documentation standards",
        "risk policy", "sla", "slo", "standard", "convention",
        "threshold remains manual",
    ))

def _assessment_blocker_classify(control, evidence, status, reason, quality, manual=False):
    """Classify why a NOT ASSESSED control cannot currently be scored.

    Metadata only: this never changes evaluator status, score, or confidence.
    Evidence-state semantics take precedence over evaluator prose.
    """
    if status != "NOT ASSESSED":
        return None
    states=quality.get("field_states",[]) if isinstance(quality,dict) else []
    sources=[x.get("source") for x in control.get("evidence",[]) if x.get("source")]

    if manual or any(_source_is_manual(x) for x in sources):
        return {"category":"MANUAL_EVIDENCE_REQUIRED",
                "detail":"Control evidence must be supplied from a manual, process, operational, identity, or governance source.",
                "sources":sources}

    feature_states=[x for x in states if x.get("availability")=="FEATURE_DISABLED"]
    if feature_states:
        return {"category":"FEATURE_NOT_ENABLED",
                "detail":"The evidence source reports the relevant GitHub feature as disabled.",
                "sources":sorted({x.get("source") for x in feature_states if x.get("source")})}

    privileged_write_states=[x for x in states if x.get("availability")=="ENDPOINT_UNAVAILABLE" and ("sensitive write" in (x.get("detail") or "").lower() or "administration: write" in (x.get("detail") or "").lower())]
    privileged_reason=("administration: write" in (reason or "").lower() or "sensitive write" in (reason or "").lower() or "bypass_actors requires write access" in (reason or "").lower())
    if privileged_write_states or privileged_reason:
        return {"category":"PRIVILEGED_ENDPOINT_REQUIRED",
                "detail":"The control depends on an endpoint/field that GitHub documents behind a sensitive write permission. The current read-only assessment intentionally does not grant that privilege.",
                "sources":sorted({x.get("source") for x in (privileged_write_states or states) if x.get("source")})}

    permission_states=[x for x in states if x.get("availability")=="ENDPOINT_UNAVAILABLE" and x.get("reason") in ("permission_denied","access_denied")]
    if permission_states or any(token in (reason or "").lower() for token in ("http_status=403", "status=403")):
        return {"category":"PERMISSION_GAP",
                "detail":"The evidence source is inaccessible with the current assessment principal; required GitHub permissions must be granted or the evidence supplied another way.",
                "sources":sorted({x.get("source") for x in (permission_states or states) if x.get("source")})}

    field_states=[x for x in states if x.get("availability")=="FIELD_UNAVAILABLE"]
    if field_states:
        return {"category":"FIELD_UNAVAILABLE",
                "detail":"The endpoint responded, but required control fields are unavailable or null.",
                "sources":sorted({x.get("source") for x in field_states if x.get("source")})}

    if any(x.get("availability")=="ENDPOINT_UNAVAILABLE" and x.get("reason") not in ("source is not collected or mapped", "permission_denied", "access_denied") for x in states):
        return {"category":"ENDPOINT_UNAVAILABLE",
                "detail":"A required evidence endpoint is unavailable or returned an unresolved API/transport error.",
                "sources":sorted({x.get("source") for x in states if x.get("availability")=="ENDPOINT_UNAVAILABLE" and x.get("source")})}

    # Explicit policy/manual semantics take precedence over an uncollected
    # source: a collector enhancement cannot resolve evidence that is
    # intrinsically an organization decision or an external process record.
    if quality.get("status")=="POLICY_REQUIRED" or _reason_is_policy(reason):
        return {"category":"POLICY_REQUIRED",
                "detail":"The available evidence is insufficient to determine an organization-specific policy, convention, standard, or threshold.",
                "sources":sources}

    if _reason_is_manual(reason) or control.get("control_id") == "GRC-124":
        return {"category":"MANUAL_EVIDENCE_REQUIRED",
                "detail":"The requirement depends on process, operational, identity, or governance evidence outside the collected GitHub inventory.",
                "sources":sources}

    # If the source itself is not collected/mapped, that is the primary
    # blocker after explicit policy/manual semantics have been evaluated.
    unmapped=[x for x in states if x.get("availability")=="ENDPOINT_UNAVAILABLE" and x.get("reason")=="source is not collected or mapped"]
    if unmapped:
        return {"category":"NOT_COLLECTED",
                "detail":"The required evidence source is known but this release does not collect or map it.",
                "sources":sorted({x.get("source") for x in unmapped if x.get("source")})}

    if not states:
        return {"category":"NOT_COLLECTED",
                "detail":"No evidence state was resolved for the control's declared evidence sources.",
                "sources":sources}

    return {"category":"ENDPOINT_UNAVAILABLE",
            "detail":"The control could not be scored because its required evidence could not be resolved.",
            "sources":sources}


def assessment_blocker(control, evidence, status, reason, quality, manual=False):
    blocker = _assessment_blocker_classify(control, evidence, status, reason, quality, manual)
    if blocker:
        resolution = blocker_resolution(blocker.get("category"))
        blocker["resolution"] = resolution["code"]
        blocker["recommended_action"] = resolution["action"]
    return blocker


PERMISSION_MANIFEST_VERSION = "1.3"
ENGINE_VERSION = "1.8.1"

# Canonical evidence-source registry. Each catalog source maps to the exact
# raw-evidence location used by collection and provenance resolution.
def assess(control,ev,manual,args):
    cid=control["control_id"]

    if cid in manual:
        m=manual[cid]
        if isinstance(m,str):
            return m,"Manual evidence supplied."
        return m.get("status","NOT ASSESSED"),m.get("reason","Manual evidence supplied.")

    org=ev.get("organization",{}).get("data",{}) if ok(ev.get("organization",{})) else {}
    repos=repo_items(ev)
    active=[r for r in repos if not r.get("archived",False)]
    owners=ev.get("owners",{}).get("items",[])
    teams=ev.get("teams",{}).get("items",[])
    outs=ev.get("outside_collaborators",{}).get("items",[])
    audit=ev.get("audit_log",{})
    orgrs=ev.get("org_rulesets",{}).get("items",[]) if ok(ev.get("org_rulesets",{})) else []
    repo_orgrs=organization_rulesets_from_repository_evidence(ev)
    effective_orgrs=orgrs if orgrs else repo_orgrs

    def org_evidence_available(key):
        item=ev.get(key,{})
        return item.get("evidence",{}).get("availability")=="AVAILABLE" or item.get("status")==200

    def repo_evidence(r):
        return ev.get("repository_evidence",{}).get(r["full_name"],{})

    def repo_rules(r):
        return merged_rules(ev,r["full_name"])

    def repo_rule_types(r):
        return rule_types(repo_rules(r))

    def envs(r):
        x=repo_data(ev,r["full_name"],"environments")
        return x.get("environments",[]) if isinstance(x,dict) else []

    def workflows(r):
        d=repo_evidence(r)
        return d.get("workflow_content",[])

    def workflow_text(r):
        return "\n".join(x.get("content","") or "" for x in workflows(r))

    def workflow_uses(r):
        return re.findall(r'(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)',workflow_text(r))

    def has_sha_pinned_action(r):
        uses=workflow_uses(r)
        if not uses:
            return True
        return all(re.search(r'@[0-9a-fA-F]{40}$',u) for u in uses)

    def has_permissions_block(r):
        return bool(re.search(r'(?m)^\s*permissions\s*:',workflow_text(r)))

    def has_concurrency(r):
        return bool(re.search(r'(?m)^\s*concurrency\s*:',workflow_text(r)))

    def has_retention(r):
        return bool(re.search(r'(?m)retention-days\s*:',workflow_text(r)))

    def has_reusable_workflow(r):
        t=workflow_text(r)
        return bool(re.search(r'\bworkflow_call\s*:',t)) or bool(
            re.search(r'uses:\s*[^@\s]+/\.github/workflows/[^@\s]+@',t)
        )

    def has_required_pr(r):
        return any(x.get("type")=="pull_request" for x in repo_rule_types(r))

    def has_required_checks(r):
        return any(x.get("type")=="required_status_checks" for x in repo_rule_types(r))

    def has_codeowners(r):
        full=r["full_name"]
        return bool(file_text(ev,full,"CODEOWNERS") or file_text(ev,full,".github/CODEOWNERS"))

    def has_security_policy(r):
        full=r["full_name"]
        return bool(file_text(ev,full,"SECURITY.md") or file_text(ev,full,".github/SECURITY.md"))

    def has_contributing(r):
        full=r["full_name"]
        return bool(file_text(ev,full,"CONTRIBUTING.md") or file_text(ev,full,".github/CONTRIBUTING.md"))

    def security_status(r,key):
        return getv(r,"security_and_analysis",key,"status")

    def aggregate(pred, label="repositories"):
        if not repos:
            return "NOT ASSESSED","Repository inventory unavailable."
        if not active:
            return "N/A","No active repositories."
        states=[bool(pred(r)) for r in active]
        good=sum(states)
        if good==len(states):
            return "PASS",f"{good}/{len(states)} {label} satisfy the control."
        if good:
            return "PARTIAL",f"{good}/{len(states)} {label} satisfy the control."
        return "FAIL",f"0/{len(states)} {label} satisfy the control."

    # ---------- Organization ----------
    if cid=="ORG-001":
        v=org.get("default_repository_permission")
        return ("PASS" if v in ("none","read") else "FAIL" if v else "NOT ASSESSED"),f"default_repository_permission={v}"
    if cid=="ORG-002":
        pub=org.get("members_can_create_public_repositories")
        private=org.get("members_can_create_private_repositories")
        if pub is None and private is None: return "NOT ASSESSED","Repository creation settings unavailable."
        return ("PASS" if pub is False and private is False else "PARTIAL"),f"public={pub}; private={private}"
    if cid=="ORG-003":
        v=org.get("members_can_create_public_repositories")
        return ("PASS" if v is False else "FAIL" if v is True else "NOT ASSESSED"),f"members_can_create_public_repositories={v}"
    if cid=="ORG-004":
        v=org.get("members_can_create_repositories")
        if v is None:
            pub=org.get("members_can_create_public_repositories")
            private=org.get("members_can_create_private_repositories")
            internal=org.get("members_can_create_internal_repositories")
            return ("PASS" if all(x is False for x in (pub,private,internal) if x is not None) and any(x is not None for x in (pub,private,internal)) else "PARTIAL" if any(x is not None for x in (pub,private,internal)) else "NOT ASSESSED"),f"creation_controls=public:{pub},private:{private},internal:{internal}"
        return ("PASS" if v is False else "PARTIAL"),f"members_can_create_repositories={v}"
    if cid=="ORG-005":
        n=len(owners)
        return ("PASS" if 1<=n<=3 else "PARTIAL" if n<=5 else "FAIL"),f"organization_owner_count={n}"
    if cid=="ORG-006":
        if not org_evidence_available("outside_collaborators"):
            return "NOT ASSESSED",f"outside_collaborators_http_status={ev.get('outside_collaborators',{}).get('status')}"
        return "PASS",f"outside_collaborators_inventoried={len(outs)}"
    if cid=="ORG-007":
        return "NOT ASSESSED","Business justification cannot be proven from GitHub inventory alone."
    if cid=="ORG-008":
        missing=[r["full_name"] for r in active if not r.get("created_at") or not r.get("pushed_at")]
        return ("PASS" if not missing else "PARTIAL"),f"active repositories with lifecycle timestamps missing={len(missing)}"
    if cid=="ORG-009":
        threshold=args.inactive_days
        now=datetime.now(timezone.utc)
        stale=0
        for r in active:
            try:
                if (now-datetime.fromisoformat(r["pushed_at"].replace("Z","+00:00"))).days>threshold:
                    stale+=1
            except Exception:
                pass
        return "INFO",f"active repositories with no push for >{threshold} days={stale}"
    if cid=="ORG-010":
        archived=sum(1 for r in repos if r.get("archived"))
        return "INFO",f"archived_repositories={archived}"

    # ---------- Identity ----------
    if cid=="IAM-011":
        saml=org.get("saml_identity_provider")
        return ("PASS" if saml else "NOT ASSESSED"),"SAML/SSO evidence present." if saml else "SSO evidence unavailable."
    if cid=="IAM-012":
        v=org.get("two_factor_requirement_enabled")
        return ("PASS" if v is True else "FAIL" if v is False else "NOT ASSESSED"),f"two_factor_requirement_enabled={v}"
    if cid=="IAM-013":
        sc=ev.get("scim_users",{})
        if sc.get("status")==200:
            data=sc.get("data") or {}
            total=data.get("totalResults") if isinstance(data,dict) else None
            return "PASS",f"SCIM provisioned identity endpoint available; totalResults={total}"
        if sc.get("status") in (404,405):
            return "N/A","SCIM organization endpoint is not available for this organization context."
        return "NOT ASSESSED","SCIM provisioning evidence was unavailable from the organization endpoint."
        # A SCIM endpoint is not exposed in the normal org payload; keep this evidence-driven.
        return "NOT ASSESSED","SCIM provisioning requires IdP/enterprise identity evidence."
    if cid=="IAM-014":
        return "NOT ASSESSED","Removal latency requires identity lifecycle history outside the repository inventory."
    if cid=="IAM-015":
        return "NOT ASSESSED","Periodic access-review cadence requires review records."
    if cid=="IAM-016":
        suspended=ev.get("suspended_members",{}).get("items",[])
        return "INFO",f"suspended_member_evidence={len(suspended)}"
    if cid=="IAM-017":
        return "NOT ASSESSED","Last-account activity evidence is not available from the collected organization inventory."
    if cid=="IAM-018":
        return "NOT ASSESSED","Enterprise-to-organization membership evidence requires enterprise identity context."

    # ---------- Teams ----------
    if cid=="TEAM-019":
        x=ev.get("team_repository_evidence",{})
        if not x:return "NOT ASSESSED","Team repository permission evidence unavailable."
        direct_admins=0
        total_team_repo=0
        for d in x.values():
            for repo in d.get("data",{}).get("items",[]) if isinstance(d.get("data"),dict) else []:
                total_team_repo+=1
        return ("PASS" if total_team_repo else "PARTIAL"),f"team-repository assignments observed={total_team_repo}"
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
    if cid=="TEAM-021":
        maintainers=sum(1 for t in teams if t.get("members_count",0)>0 and t.get("permission")=="maintain")
        return "INFO",f"team_maintainer_evidence={maintainers}"
    if cid=="TEAM-022":
        nested=sum(1 for t in teams if t.get("parent"))
        return "INFO",f"nested_teams={nested}"
    if cid=="TEAM-023":
        return "NOT ASSESSED","Team ownership requires explicit owner evidence; description alone is insufficient."
    if cid=="TEAM-024":
        if not org_evidence_available("teams"):
            return "NOT ASSESSED",f"teams_http_status={ev.get('teams',{}).get('status')}"
        empty=sum(1 for t in teams if t.get("members_count",0)==0)
        return ("PASS" if empty==0 else "PARTIAL"),f"empty_teams={empty}"
    if cid=="TEAM-025":
        if not org_evidence_available("teams"):
            return "NOT ASSESSED",f"teams_http_status={ev.get('teams',{}).get('status')}"
        no_repo=sum(1 for t in teams if t.get("repos_count",0)==0)
        return ("PASS" if no_repo==0 else "PARTIAL"),f"teams_without_repositories={no_repo}"
    if cid=="TEAM-026":
        return "NOT ASSESSED","Sensitive-repository classification and dedicated-group intent require organizational evidence."

    # ---------- Repository governance ----------
    if cid=="REPO-027":
        return aggregate(has_codeowners)
    if cid=="REPO-028":
        return aggregate(lambda r:r.get("visibility") in ("private","internal","public"))
    if cid=="REPO-029":
        return "NOT ASSESSED","Public-repository approval records are outside the GitHub repository object."
    if cid=="REPO-030":
        internal=sum(1 for r in active if r.get("visibility")=="internal")
        return "INFO",f"internal_repositories={internal}/{len(active)}"
    if cid=="REPO-031":
        return aggregate(lambda r:bool(r.get("description")))
    if cid=="REPO-032":
        return aggregate(lambda r:bool(r.get("topics")))
    if cid=="REPO-033":
        archived=[r for r in repos if r.get("archived")]
        return ("PASS" if all(r.get("archived") for r in archived) else "PARTIAL"),f"archived_repositories={len(archived)}"
    if cid=="REPO-034":
        templates=sum(1 for r in repos if r.get("is_template"))
        return "INFO",f"template_repositories={templates}"
    if cid=="REPO-035":
        return "NOT ASSESSED","Naming compliance requires an organization-specific naming convention."
    if cid=="REPO-036":
        return "INFO",f"repositories_allowing_forks={sum(1 for r in active if r.get('allow_forking'))}/{len(active)}"

    # ---------- Source control ----------
    if cid=="SCM-037":
        return aggregate(lambda r:bool(repo_rules(r)))
    if cid=="SCM-038":
        return aggregate(lambda r:has_required_pr(r))
    if cid=="SCM-039":
        return aggregate(lambda r:any(x.get("type")=="non_fast_forward" for x in repo_rule_types(r)))
    if cid=="SCM-040":
        return aggregate(lambda r:any(x.get("type")=="deletion" for x in repo_rule_types(r)))
    if cid=="SCM-041":
        return aggregate(lambda r:any(x.get("type") in ("required_signatures","required_commit_signatures") for x in repo_rule_types(r)))
    if cid=="SCM-042":
        if org_evidence_available("org_rulesets"):
            active_org=[x for x in orgrs if x.get("enforcement")=="active"]
            return ("PASS" if active_org else "FAIL"),f"active_organization_rulesets={len(active_org)}/{len(orgrs)}"
        # Least-privilege fallback: repository rulesets with includes_parents=true
        # expose active organization-origin rulesets without requiring org-level
        # Administration: write.
        active_org=[x for x in repo_orgrs if x.get("enforcement") in ("active","enabled")]
        if repo_orgrs:
            return ("PASS" if active_org else "FAIL"),f"active_organization_rulesets_from_repository_scope={len(active_org)}/{len(repo_orgrs)}"
        return "NOT ASSESSED",f"Organization rulesets require Administration: write; repository-scoped rulesets are available but expose only {len(repo_orgrs)} Organization-origin rulesets for this repository population."
    if cid=="SCM-043":
        if org_evidence_available("org_rulesets"):
            targeted=sum(1 for x in orgrs if x.get("enforcement")=="active" and x.get("conditions"))
            return ("PASS" if targeted else "FAIL"),f"active_org_rulesets_with_target_conditions={targeted}/{len(orgrs)}"
        # The repository ruleset list is intentionally conservative: GitHub's
        # read-only list representation may omit conditions. Do not infer target
        # coverage from a missing field.
        if repo_orgrs:
            return "NOT ASSESSED", "Repository-scoped rulesets are available, but target conditions are not exposed by the least-privilege list response."
        return "NOT ASSESSED",f"Organization rulesets require Administration: write; repository-scoped rulesets are available but expose only {len(repo_orgrs)} Organization-origin rulesets for this repository population."
    if cid=="SCM-044":
        return aggregate(lambda r:has_required_checks(r) and has_required_pr(r))
    if cid=="SCM-045":
        source=effective_orgrs
        tag_rules=sum(1 for x in source if x.get("target")=="tag" and x.get("enforcement") in ("active","enabled"))
        
        if not source:
            return "NOT ASSESSED", "Organization tag rulesets require Administration: write for direct enumeration; repository-scoped rulesets did not expose Organization-origin tag rulesets."
        return ("PASS" if tag_rules else "PARTIAL"),f"active_organization_tag_rulesets={tag_rules}"
    if cid=="SCM-046":
        # bypass_actors is intentionally treated as field-sensitive. GitHub
        # documents that this field is only returned with write access to the
        # ruleset, so a read-only App must not interpret absence as zero bypasses.
        if org_evidence_available("org_rulesets"):
            if any("bypass_actors" not in x for x in orgrs if x.get("enforcement")=="active"):
                return "NOT ASSESSED", "Organization rulesets are available, but bypass_actors is not exposed to the read-only assessment principal."
            bypass=sum(1 for x in orgrs if x.get("enforcement")=="active" and x.get("bypass_actors"))
            return ("PASS" if bypass==0 else "PARTIAL"),f"active_rulesets_with_bypass_actors={bypass}"
        if repo_orgrs:
            return "NOT ASSESSED", "Repository rulesets are available, but bypass_actors requires write access to the ruleset and is intentionally not inferred."
        return "NOT ASSESSED",f"Organization rulesets require Administration: write; repository-scoped rulesets are available but expose only {len(repo_orgrs)} Organization-origin rulesets for this repository population."

    # ---------- Review ----------
    if cid=="REV-047":
        return aggregate(has_required_pr)
    if cid=="REV-048":
        vals=[]
        for r in active:
            found=False
            for rs in repo_rules(r):
                for rule in rs.get("rules",[]):
                    if rule.get("type")=="pull_request":
                        p=rule.get("parameters",{})
                        found = p.get("required_approving_review_count",0) > 0 or found
            vals.append(found)
        if not vals:return "NOT ASSESSED","Pull-request rule evidence unavailable."
        return ("PASS" if all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"repositories with approving-review requirement={sum(vals)}/{len(vals)}"
    if cid=="REV-049":
        return aggregate(has_codeowners)
    if cid=="REV-050":
        vals=[]
        for r in active:
            vals.append(any(
                rule.get("parameters",{}).get("dismiss_stale_reviews") is True
                for rs in repo_rules(r) for rule in rs.get("rules",[]) if rule.get("type")=="pull_request"
            ))
        return ("PASS" if vals and all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"repositories dismissing stale reviews={sum(vals)}/{len(vals)}"
    if cid=="REV-051":
        vals=[]
        for r in active:
            vals.append(any(
                bool(rule.get("parameters",{}).get("dismissal_restrictions"))
                for rs in repo_rules(r) for rule in rs.get("rules",[]) if rule.get("type")=="pull_request"
            ))
        return ("PASS" if vals and all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"repositories with review dismissal restrictions={sum(vals)}/{len(vals)}"
    if cid=="REV-052":
        return aggregate(lambda r:any(x.get("type")=="required_conversation_resolution" for x in repo_rule_types(r)))
    if cid=="REV-053":
        return "NOT ASSESSED","Security finding review workflow, ownership and SLA require process evidence."
    if cid=="REV-054":
        return "NOT ASSESSED","Documentation standards require an organization-defined standard."

    # ---------- Actions ----------
    ap=ev.get("actions_permissions",{}).get("data",{}) if ok(ev.get("actions_permissions",{})) else {}
    selected=ev.get("actions_selected",{}).get("data",{}) if ok(ev.get("actions_selected",{})) else {}
    if cid=="CI-055":
        return aggregate(has_required_checks)
    if cid=="CI-056":
        return aggregate(has_reusable_workflow)
    if cid=="CI-057":
        vals=[has_permissions_block(r) for r in active if workflows(r)]
        if not vals:return "NOT ASSESSED","Workflow content unavailable."
        # Presence alone is not sufficient; reject explicit write-all defaults.
        bad=sum(1 for r in active if workflows(r) and bool(re.search(r'permissions:\s*write-all',workflow_text(r))))
        return ("PASS" if bad==0 and all(vals) else "PARTIAL" if bad<len(vals) else "FAIL"),f"workflow repositories with explicit permission blocks={sum(vals)}/{len(vals)}; write-all patterns={bad}"
    if cid=="CI-058":
        # GitHub returns HTTP 409 when the organization allows all Actions.
        # That is valid policy evidence, not an unavailable endpoint.
        raw=ev.get("actions_selected",{})
        if raw.get("status")==409 and str((raw.get("data") or {}).get("errors","")).lower().find("all actions") >= 0:
            return "FAIL","Organization Actions policy allows all actions and workflows; no approved-source restriction is enforced."
        if not selected:return "NOT ASSESSED","Organization Actions selected-policy evidence unavailable."
        allowed=selected.get("github_owned_allowed")
        verified=selected.get("verified_allowed")
        patterns=selected.get("patterns_allowed",[])
        return ("PASS" if allowed is True and verified is True else "PARTIAL" if any(x is not None for x in (allowed,verified)) else "NOT ASSESSED"),f"github_owned_allowed={allowed}; verified_allowed={verified}; patterns={len(patterns)}"
    if cid=="CI-059":
        raw=ev.get("actions_selected",{})
        if raw.get("status")==409 and str((raw.get("data") or {}).get("errors","")).lower().find("all actions") >= 0:
            return "FAIL","Third-party Actions are not restricted by organization policy because all Actions and workflows are allowed."
        # Governance can be objectively assessed when the organization restricts
        # Actions sources and workflow references are pinned.
        if not selected:return "NOT ASSESSED","Selected Actions policy unavailable."
        pinned=all(has_sha_pinned_action(r) for r in active if workflows(r))
        governed=selected.get("github_owned_allowed") is True or selected.get("patterns_allowed")
        return ("PASS" if governed and pinned else "PARTIAL" if governed or pinned else "FAIL"),f"source_policy={governed}; all_workflow_actions_sha_pinned={pinned}"
    if cid=="CI-060":
        vals=[has_sha_pinned_action(r) for r in active if workflows(r)]
        if not vals:return "NOT ASSESSED","Workflow content unavailable."
        return ("PASS" if all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"workflow repositories with SHA-pinned Actions={sum(vals)}/{len(vals)}"
    if cid=="CI-061":
        vals=[]
        for r in active:
            production=[e for e in envs(r) if str(e.get("name","")).lower() in ("prod","production")]
            vals.append(bool(production and any(e.get("protection_rules") for e in production)))
        return ("PASS" if vals and all(vals) else "PARTIAL" if any(vals) else "NOT ASSESSED"),f"repositories with protected production environments={sum(vals)}/{len(vals)}"
    if cid=="CI-062":
        vals=[]; applicable=0; unavailable=0
        for r in active:
            production=[e for e in envs(r) if str(e.get("name","")).lower() in ("prod","production")]
            if not production: continue
            applicable += 1
            per_repo=repo_evidence(r).get("environment_secrets_by_name",{})
            if any(per_repo.get(e.get("name"),{}).get("status") != 200 for e in production):
                unavailable += 1
                vals.append(False)
            else:
                vals.append(True)
        if applicable==0:return "N/A","No production/prod environments were identified in the collected environment inventory."
        if unavailable==applicable:return "NOT ASSESSED",f"environment secret evidence unavailable for {unavailable}/{applicable} production repositories"
        good=sum(vals)
        return ("PASS" if good==applicable else "PARTIAL" if good else "FAIL"),f"repositories with restricted production environment secret evidence={good}/{applicable}"
    if cid=="CI-063":
        vals=[]; applicable=0
        for r in active:
            production=[e for e in envs(r) if str(e.get("name","")).lower() in ("prod","production")]
            if not production: continue
            applicable += 1
            vals.append(all(e.get("deployment_branch_policy") is not None for e in production))
        if applicable==0:return "N/A","No production/prod environments were identified in the collected environment inventory."
        good=sum(vals)
        return ("PASS" if good==applicable else "PARTIAL" if good else "FAIL"),f"repositories with deployment branch policy evidence={good}/{applicable}"
    if cid=="CI-064":
        p=ev.get("self_hosted_runner_policy",{})
        return ("PASS" if p.get("status")==200 else "NOT ASSESSED"),f"self_hosted_runner_policy_status={p.get('status')}"
    if cid=="CI-065":
        raw=ev.get("runner_groups",{})
        data=raw.get("data") if isinstance(raw.get("data"),dict) else {}
        groups=data.get("runner_groups",[]) if isinstance(data,dict) else []
        if raw.get("status") != 200:return "NOT ASSESSED",f"runner_groups_status={raw.get('status')}"
        restricted=[g for g in groups if g.get("visibility")=="selected" or g.get("selected_repositories_url")]
        return ("PASS" if restricted else "PARTIAL" if groups else "NOT ASSESSED"),f"runner_groups={len(groups)}; restricted_groups={len(restricted)}"
    if cid=="CI-066":
        vals=[has_concurrency(r) for r in active if workflows(r)]
        if not vals:return "NOT ASSESSED","Workflow content unavailable."
        return ("PASS" if all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"workflow repositories with concurrency={sum(vals)}/{len(vals)}"
    if cid=="CI-067":
        vals=[has_retention(r) for r in active if workflows(r)]
        if not vals:return "NOT ASSESSED","Workflow content unavailable."
        return ("PARTIAL" if any(vals) else "NOT ASSESSED"),f"workflow repositories explicitly setting retention-days={sum(vals)}/{len(vals)}; policy threshold remains manual"
    if cid=="CI-068":
        return "NOT ASSESSED","Rollback procedures and test evidence require operational documentation."

    # ---------- Security ----------
    if cid=="SEC-069":
        return aggregate(lambda r:security_status(r,"dependency_graph")=="enabled")
    if cid=="SEC-070":
        return aggregate(lambda r:security_status(r,"dependabot_security_updates")=="enabled" or bool(repo_evidence(r).get("dependabot")))
    if cid=="SEC-071":
        return aggregate(lambda r:security_status(r,"dependabot_security_updates")=="enabled")
    if cid=="SEC-072":
        return aggregate(lambda r:security_status(r,"secret_scanning")=="enabled")
    if cid=="SEC-073":
        return aggregate(lambda r:security_status(r,"secret_scanning_push_protection")=="enabled")
    if cid=="SEC-074":
        vals=[repo_evidence(r).get("code_scanning",{}).get("status")==200 for r in active]
        return ("PASS" if vals and all(vals) else "PARTIAL" if any(vals) else "NOT ASSESSED"),f"repositories with code-scanning API evidence={sum(vals)}/{len(vals)}"
    if cid=="SEC-075":
        return aggregate(has_security_policy)
    if cid in ("SEC-076","SEC-077","SEC-078"):
        return "NOT ASSESSED","This requirement needs an organization-defined SLA, dependency-risk policy, or SBOM strategy."
    if cid=="SEC-079":
        vals=[has_sha_pinned_action(r) for r in active if workflows(r)]
        if not vals:return "NOT ASSESSED","Workflow content unavailable."
        return ("PASS" if all(vals) else "PARTIAL" if any(vals) else "FAIL"),f"workflow repositories with SHA-pinned third-party Actions={sum(vals)}/{len(vals)}"
    if cid=="SEC-080":
        raw=ev.get("attestation_repositories",{})
        # The organization inventory is the only source used to establish
        # repository-level attestation coverage. A 404/403/5xx is evidence
        # unavailability, not evidence that artifacts lack attestations.
        if raw.get("status")==200:
            items=raw.get("items",[]) if isinstance(raw.get("items"),list) else []
            names={str(x.get("name")) for x in items if isinstance(x,dict) and x.get("name")}
            applicable=len(active)
            covered=sum(1 for r in active if r.get("name") in names or r.get("full_name","").split("/",1)[-1] in names)
            return ("PASS" if applicable and covered==applicable else "PARTIAL" if covered else "FAIL"),f"repositories with artifact attestations={covered}/{applicable}"
        return "NOT ASSESSED","Organization artifact-attestation repository inventory was unavailable; absence of API evidence is not treated as absence of attestations."
    if cid=="SEC-081":
        cs=ev.get("org_code_scanning_alerts",{})
        ss=ev.get("org_secret_scanning_alerts",{})
        available=[x for x in (cs,ss) if x.get("status")==200]
        if not available:
            return "NOT ASSESSED","Organization-level security alert inventory was unavailable."
        # API inventory proves technical visibility only. The control also
        # requires centralized ownership/aggregation/operational process
        # evidence (for example SIEM routing, security ownership and triage).
        # Therefore technical visibility must never be promoted to PASS.
        counts=[]
        if cs.get("status")==200: counts.append(f"code-scanning alerts={len(cs.get('items',[]))}")
        if ss.get("status")==200: counts.append(f"secret-scanning alerts={len(ss.get('items',[]))}")
        return "NOT ASSESSED","Technical security-alert inventory is available, but centralized ownership, aggregation and operational triage require governance/process evidence; " + "; ".join(counts)

    # ---------- Shared platform ----------
    if cid=="SUP-082":
        shared=[r for r in active if re.search(r"(?m)^\s*workflow_call\s*:",workflow_text(r))]
        if not shared:return "N/A","No reusable workflow repositories were identified from workflow_call definitions."
        owned=sum(1 for r in shared if has_codeowners(r))
        return ("PASS" if owned==len(shared) else "PARTIAL" if owned else "FAIL"),f"shared workflow repositories with CODEOWNERS evidence={owned}/{len(shared)}"
    if cid=="SUP-083":
        return "NOT ASSESSED","Workflow versioning policy requires release/tag evidence for identified shared components."
    if cid=="SUP-084":
        return aggregate(has_contributing)
    if cid in ("SUP-085","SUP-086","SUP-087","SUP-088","SUP-089"):
        return "NOT ASSESSED","Shared-component inventory, lifecycle, review and adoption evidence requires organizational context."

    # ---------- Operations ----------
    if cid=="OPS-090":
        return ("PASS" if audit.get("status")==200 else "NOT ASSESSED"),f"audit_log_http_status={audit.get('status')}"
    if cid in ("OPS-091","OPS-092","OPS-093","OPS-094","OPS-095","OPS-096","OPS-097","OPS-098","OPS-099"):
        return "NOT ASSESSED","Retention, monitoring destinations, alert rules and SLO/SLA evidence are not derivable from the raw audit/workflow inventory alone."

    # ---------- Disaster recovery ----------
    if cid.startswith("DR-"):
        return "NOT ASSESSED","Independent recovery, RPO/RTO and recovery-exercise evidence requires external operational evidence."

    # ---------- Productivity ----------
    if cid=="PROD-110":
        templates=sum(1 for r in repos if r.get("is_template"))
        return ("PASS" if templates else "PARTIAL"),f"template_repositories={templates}"
    if cid in ("PROD-111","PROD-112","PROD-113","PROD-114","PROD-115","PROD-116","PROD-117"):
        return "NOT ASSESSED","Developer-productivity standards require organization-level process or platform evidence."

    # ---------- GRC ----------
    if cid.startswith("GRC-"):
        return "NOT ASSESSED","Governance register, exception, risk acceptance and remediation ownership require external control evidence."

    # ---------- Cost / AI ----------
    if cid.startswith("COST-"):
        return "NOT ASSESSED","Billing, AI credit, Actions compute and cost-attribution evidence require applicable billing/enterprise APIs or manual evidence."

    return "NOT ASSESSED",f"No specific adapter registered for {cid}."

