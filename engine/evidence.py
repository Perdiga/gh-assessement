"""Evidence source mapping, normalization, quality, and coverage helpers."""

import re

SOURCE_REGISTRY = {
    "GET /orgs/{org}": {"scope": "org", "key": "organization"},
    "GET /orgs/{org}/members?role=admin": {"scope": "org", "key": "owners"},
    "GET /orgs/{org}/members": {"scope": "org", "key": "members"},
    "GET /orgs/{org}/outside-collaborators": {"scope": "org", "key": "outside_collaborators"},
    "GET /orgs/{org}/teams": {"scope": "org", "key": "teams"},
    "GET /orgs/{org}/rulesets": {"scope": "org", "key": "org_rulesets"},
    "GET /orgs/{org}/audit-log": {"scope": "org", "key": "audit_log"},
    "GET /orgs/{org}/attestations/repositories": {"scope": "org", "key": "attestation_repositories"},
    "GET /orgs/{org}/code-scanning/alerts": {"scope": "org", "key": "org_code_scanning_alerts"},
    "GET /orgs/{org}/secret-scanning/alerts": {"scope": "org", "key": "org_secret_scanning_alerts"},
    "GET /scim/v2/organizations/{org}/Users": {"scope": "org", "key": "scim_users"},
    "GET /orgs/{org}/actions/permissions": {"scope": "org", "key": "actions_permissions"},
    "GET /orgs/{org}/actions/permissions/selected-actions": {"scope": "org", "key": "actions_selected"},
    "GET /orgs/{org}/actions/permissions/workflow": {"scope": "org", "key": "actions_workflow_permissions"},
    "GET /orgs/{org}/actions/permissions/self-hosted-runners": {"scope": "org", "key": "self_hosted_runner_policy"},
    "GET /orgs/{org}/actions/runner-groups": {"scope": "org", "key": "runner_groups"},
    "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets": {"scope": "repo", "key": "environment_secrets_by_name"},
    "GET /repos/{owner}/{repo}/attestations": {"scope": "repo", "key": "attestations"},
    "GET /orgs/{org}/repos": {"scope": "org", "key": "repositories"},
    "Repository inventory": {"scope": "org", "key": "repositories"},
}

def source_registry_entry(source):
    return SOURCE_REGISTRY.get(source)


# Expected minimum read permissions for automated API evidence. These are
# guidance for the assessment principal; observed X-Accepted-GitHub-Permissions
# headers are authoritative when GitHub returns them.
def permission_requirements(source):
    s = source or ""
    if s.startswith("GET /orgs/{org}/members") or "outside-collaborators" in s or "/teams" in s or s.startswith("GET /scim/"):
        return [{"scope":"organization","permission":"Members","access":"read"}]
    if s == "GET /orgs/{org}/code-scanning/alerts":
        return [{"scope":"repository","permission":"Code scanning alerts","access":"read"}]
    if s == "GET /orgs/{org}/secret-scanning/alerts":
        return [{"scope":"repository","permission":"Secret scanning alerts","access":"read"}]
    if s == "GET /orgs/{org}/attestations/repositories":
        return [{"scope":"repository","permission":"Attestations","access":"read"}]
    if "/actions/" in s and s.startswith("GET /orgs/{org}"):
        return [{"scope":"organization","permission":"Administration","access":"read"}]
    if s == "GET /orgs/{org}/rulesets":
        # GitHub currently requires Organization Administration: write for
        # organization-level rulesets, even for GET. This is intentionally
        # marked as a sensitive write permission in the permission audit.
        return [{"scope":"organization","permission":"Administration","access":"write","sensitivity":"SENSITIVE_WRITE_REQUIRED","required":False,"mode":"OPTIONAL_DIRECT","reason":"Direct organization-ruleset enumeration requires a sensitive write permission; v1.7.4 uses repository-scoped rulesets with includes_parents=true as the least-privilege fallback."}]
    if s == "GET /orgs/{org}/audit-log":
        return [{"scope":"organization","permission":"Administration","access":"read"}]
    if s == "GET /orgs/{org}":
        return [{"scope":"organization","permission":"Administration","access":"read"}]
    if s.startswith("GET /orgs/{org}"):
        return [{"scope":"organization","permission":"Administration","access":"read"}]
    if s.startswith("GET /repos/{owner}/{repo}/rulesets"):
        return [{"scope":"repository","permission":"Metadata","access":"read"}]
    if s.startswith("GET /repos/{owner}/{repo}"):
        # Most repository metadata/rules endpoints require repository Metadata
        # read; Actions settings use Administration read and security APIs have
        # their own read permissions. Keep the manifest explicit but non-fatal.
        if "/actions/" in s:
            return [{"scope":"repository","permission":"Administration","access":"read"}]
        if "/code-scanning/" in s:
            return [{"scope":"repository","permission":"Code scanning alerts","access":"read"}]
        if "/secret-scanning/" in s:
            return [{"scope":"repository","permission":"Secret scanning alerts","access":"read"}]
        if "/dependabot/" in s:
            return [{"scope":"repository","permission":"Dependabot alerts","access":"read"}]
        if "/attestations" in s:
            return [{"scope":"repository","permission":"Attestations","access":"read"}]
        if "/environments/" in s and "/secrets" in s:
            return [{"scope":"repository","permission":"Secrets","access":"read"}]
        if "/contents/" in s:
            return [{"scope":"repository","permission":"Contents","access":"read"}]
        return [{"scope":"repository","permission":"Metadata","access":"read"}]
    return []

def _permission_key(scope, permission):
    """Map our normalized evidence permission labels to GitHub App manifest keys.

    GitHub App installation metadata uses different keys for some permissions
    than the human-readable API permission names used by our control catalog.
    Keep that translation in one place so the audit compares like-for-like.
    """
    p=(permission or "").strip().lower().replace(" ","_").replace("-","_")
    aliases={
        ("organization", "members"): "members",
        ("organization", "administration"): "organization_administration",
        ("repository", "code_scanning_alerts"): "security_events",
        ("repository", "code_scanning_alerts"): "security_events",
        ("repository", "dependabot_alerts"): "vulnerability_alerts",
    }
    return aliases.get((scope, p), ("organization_" + p) if scope == "organization" else p)

def permission_audit(auth_metadata, catalog):
    """Audit granted GitHub App permissions against the minimum control matrix."""
    granted=(auth_metadata or {}).get("permissions",{}) or {}
    required={}
    for control in catalog.get("controls",[]):
        for evidence in control.get("evidence",[]):
            for req in permission_requirements(evidence.get("source")):
                key=_permission_key(req.get("scope"),req.get("permission"))
                if req.get("required",True) is False:
                    continue
                access=req.get("access","read")
                rank=1 if access=="read" else 2
                current=required.get(key)
                if current is None or rank > current.get("rank",0):
                    required[key]={"access":access,"rank":rank,"controls":[]}
                required[key]["controls"].append(control.get("control_id"))
    missing=[]; elevated=[]; unnecessary_write=[]
    for key, req in sorted(required.items()):
        actual=granted.get(key)
        if actual is None:
            missing.append({"permission":key,"required_access":req["access"],"controls":sorted(set(req["controls"]))})
        elif req["access"]=="read" and actual=="write":
            elevated.append({"permission":key,"required_access":"read","granted_access":"write","controls":sorted(set(req["controls"]))})
    for key, actual in sorted(granted.items()):
        if actual != "write":
            continue
        req=required.get(key)
        if req is None:
            unnecessary_write.append({"permission":key,"granted_access":"write","reason":"No assessment control requires this permission."})
    # Missing permissions are an assessment-coverage problem, not a write-risk
    # violation. Keep the security posture read-only while surfacing incomplete
    # permission coverage as WARNING.
    status = "FAIL" if unnecessary_write else (
        "WARN" if (elevated or missing) else "PASS"
    )
    return {
        "status": status,
        "read_only_assessment": not bool(unnecessary_write or elevated),
        "required_permissions": {k:{"access":v["access"],"controls":sorted(set(v["controls"]))} for k,v in sorted(required.items())},
        "missing_required_permissions": missing,
        "elevated_permissions": elevated,
        "unnecessary_write_permissions": unnecessary_write,
        "notes":[
            "Organization rulesets require Administration: write for the direct GET endpoint; v1.7.3 treats that permission as optional because repository-scoped rulesets with includes_parents=true provide the least-privilege fallback." ,
            "Repository rulesets are collected with Metadata: read and includes_parents=true as the preferred least-privilege fallback."
        ]
    }

def _source_evidence_item(evidence, source):
    """Return the normalized evidence object for an assessment evidence source."""
    entry = source_registry_entry(source)
    if entry and entry.get("scope") == "org":
        return evidence.get(entry["key"],{})
    return None

def _field_names(field):
    return [x.strip() for x in str(field or "").split(",") if x.strip()]

def canonical_field(field):
    aliases={"default_repo_permission":"default_repository_permission"}
    return aliases.get(str(field),str(field))

def _has_field(obj, field):
    """True when a required field exists and is not None. Supports dotted paths."""
    cur=obj
    for part in canonical_field(field).split("."):
        if isinstance(cur,dict) and part in cur:
            cur=cur[part]
        else:
            return False
    return cur is not None

def _repo_field_states(evidence, source, field):
    """Resolve fields from the actual repository evidence structure.

    The collector stores repository evidence by endpoint key, not as a flat
    source map. A source such as /repos/{owner}/{repo} therefore needs to be
    resolved against every repository before field availability can be known.
    """
    repo_names=[r.get("full_name") for r in repo_items(evidence) if r.get("full_name")]
    if not repo_names:
        return [{"source":source,"field":field,"availability":"ENDPOINT_UNAVAILABLE","reason":"repository inventory unavailable"}]

    if "/contents/" in source:
        path=source.split("/contents/",1)[1]
        # CODEOWNERS and policy files can live at the repository root or under .github.
        if path in ("CODEOWNERS", "SECURITY.md", "CONTRIBUTING.md"):
            candidate_paths=[path, f".github/{path}"]
        elif path == ".github/workflows":
            # Workflow directory evidence is collected as workflow metadata plus
            # the fetched workflow contents, not through repository_evidence.files.
            available=0
            missing=0
            for name in repo_names:
                d=evidence.get("repository_evidence",{}).get(name,{})
                wf=d.get("workflow_files",{})
                wc=d.get("workflow_content",[])
                if isinstance(wf,dict) and isinstance(wf.get("items"),list):
                    available += 1
                    if wf.get("items") and (not isinstance(wc,list) or len(wc) < len(wf.get("items",[]))):
                        missing += 1
                else:
                    missing += 1
            return [{"source":source,"field":field,
                     "availability":"FIELD_UNAVAILABLE" if missing else "AVAILABLE",
                     "population":len(repo_names),"rows_missing_fields":missing,
                     "derived_from":"workflow_files + workflow_content"}]
        else:
            candidate_paths=[path]
        values=[]
        for name in repo_names:
            files=evidence.get("repository_evidence",{}).get(name,{}).get("files",{})
            candidates = []
            if isinstance(files, dict):
                for path in candidate_paths:
                    candidate = files.get(path)
                    if isinstance(candidate, dict):
                        candidates.append(candidate)
            item=next((x for x in candidates if x.get("status")==200), candidates[0] if candidates else None)
            if isinstance(item,dict):
                values.append(item)
            else:
                values.append(None)
        available=sum(1 for x in values if isinstance(x,dict) and x.get("status")==200)
        if available == 0:
            return [{"source":source,"field":field,"availability":"ENDPOINT_UNAVAILABLE","reason":"file endpoint unavailable for all repositories","population":len(repo_names)}]
        missing=[]
        for item in values:
            if not isinstance(item,dict) or item.get("status")!=200:
                missing.append(True)
                continue
            data=item.get("data")
            missing.append(not all(_has_field(data,x) for x in _field_names(field)))
        missing_count=sum(missing)
        return [{"source":source,"field":field,
                 "availability":"FIELD_UNAVAILABLE" if missing_count else "AVAILABLE",
                 "population":len(repo_names),"available":available,
                 "rows_missing_fields":missing_count}]

    endpoint_map={
        "/collaborators":"collaborators",
        "/rulesets":"rulesets",
        "/environments/":"environments",
        "/environments":"environments",
        "/actions/workflows":"workflows",
        "/code-scanning/analyses":"code_scanning",
        "/secret-scanning/alerts":"secret_scanning",
        "/dependabot/alerts":"dependabot",
        "/rules/branches/":"default_branch_rules",
        "/branches/{branch}/protection":"default_branch_rules",
    }
    key="repo"
    for marker,candidate in endpoint_map.items():
        if marker in source:
            key=candidate
            break

    values=[]
    for name in repo_names:
        item=evidence.get("repository_evidence",{}).get(name,{}).get(key)
        values.append(item if isinstance(item,dict) else None)

    # A repository-level endpoint can legitimately return an empty collection.
    # In that case the collection itself is available; an empty result is not
    # a missing field.
    endpoint_unavailable=sum(1 for x in values if not isinstance(x,dict) or x.get("status") != 200)
    if endpoint_unavailable == len(values):
        reasons=[]
        for x in values:
            if isinstance(x,dict):
                reasons.append(x.get("evidence",{}).get("reason"))
        return [{"source":source,"field":field,"availability":"ENDPOINT_UNAVAILABLE",
                 "reason":next((r for r in reasons if r),"endpoint unavailable"),
                 "population":len(repo_names)}]

    missing_count=0
    for item in values:
        if not isinstance(item,dict) or item.get("status") != 200:
            missing_count += 1
            continue
        data=item.get("data")
        # Normalize catalog field names to the actual GitHub REST response fields.
        field_aliases={
            "security_and_analysis.secret_scanning.push_protection":"security_and_analysis.secret_scanning_push_protection",
            "security_and_analysis.dependabot_security_updates":"security_and_analysis.dependabot_security_updates",
        }
        effective_fields=[field_aliases.get(x,x) for x in _field_names(field)]
        if key == "environments" and isinstance(data,dict):
            rows=data.get("environments",[])
        elif key == "workflows" and isinstance(data,dict):
            rows=data.get("workflows",[])
        elif isinstance(data,list):
            rows=data
        elif isinstance(data,dict):
            rows=[data]
        else:
            rows=[]

        # Empty collections are valid evidence for collection controls. For
        # fields that describe objects inside a collection, there are simply
        # zero returned objects to inspect.
        if not rows:
            continue
        if not all(all(_has_field(row,x) for x in effective_fields) for row in rows if isinstance(row,dict)):
            missing_count += 1

    availability="FIELD_UNAVAILABLE" if missing_count else "AVAILABLE"
    return [{"source":source,"field":field,"availability":availability,
             "population":len(repo_names),"rows_missing_fields":missing_count,
             "endpoint_unavailable":endpoint_unavailable}]

def evidence_field_states(control, evidence):
    """Resolve field-level availability without conflating HTTP 200 with field availability."""
    states=[]
    for evdef in control.get("evidence",[]):
        source=evdef.get("source")
        field=evdef.get("field")
        if not source:
            continue

        if source.startswith("GET /repos/{owner}/{repo}"):
            states.extend(_repo_field_states(evidence,source,field))
            continue

        item=_source_evidence_item(evidence,source)
        if item is None:
            states.append({"source":source,"field":field,"availability":"ENDPOINT_UNAVAILABLE","reason":"source is not collected or mapped"})
            continue
        evstate=item.get("evidence",{}) if isinstance(item,dict) else {}
        availability=evstate.get("availability")
        if evstate.get("reason")=="feature_disabled":
            states.append({"source":source,"field":field,"availability":"FEATURE_DISABLED","reason":"feature_disabled"})
            continue
        if availability and availability != "AVAILABLE":
            states.append({"source":source,"field":field,"availability":"ENDPOINT_UNAVAILABLE","reason":evstate.get("reason")})
            continue
        if isinstance(item,dict) and isinstance(item.get("data"),dict):
            missing=[x for x in _field_names(field) if not _has_field(item["data"],x)]
            states.append({"source":source,"field":field,"availability":"FIELD_UNAVAILABLE" if missing else "AVAILABLE","missing_fields":missing})
            continue
        if isinstance(item,dict) and isinstance(item.get("items"),list):
            items=item["items"]
            if not items:
                states.append({"source":source,"field":field,"availability":"AVAILABLE","population":0,"note":"empty_collection"})
            else:
                aliases={"archive":"archived"}
                effective_fields=[aliases.get(x,x) for x in _field_names(field)]
                missing_count=sum(1 for row in items if not all(_has_field(row,x) for x in effective_fields))
                states.append({"source":source,"field":field,"availability":"FIELD_UNAVAILABLE" if missing_count else "AVAILABLE","population":len(items),"rows_missing_fields":missing_count})
            continue
        states.append({"source":source,"field":field,"availability":"FIELD_UNAVAILABLE","reason":"required field could not be resolved"})
    return states

def evidence_quality_for_control(control, evidence, assessment_status=None, assessment_reason=None):
    """Assess evidence quality, separating evidence gaps from policy gaps."""
    warnings=[]
    states=evidence_field_states(control,evidence)
    for state in states:
        if state.get("availability")=="FIELD_UNAVAILABLE":
            warnings.append({"source":state.get("source"),"code":"FIELD_UNAVAILABLE","message":"Endpoint responded, but one or more fields required by the control were unavailable or null.","field":state.get("field"),"missing_fields":state.get("missing_fields",[])})
        elif state.get("availability")=="ENDPOINT_UNAVAILABLE":
            warnings.append({"source":state.get("source"),"code":"ENDPOINT_UNAVAILABLE","message":"The evidence endpoint was unavailable or inaccessible.","reason":state.get("reason")})
    for src in [x.get("source") for x in control.get("evidence",[]) if x.get("source")]:
        if src == "GET /orgs/{org}/members?role=admin":
            item=evidence.get("owners",{})
            if item.get("status")==200 and isinstance(item.get("items"),list) and len(item["items"])==0:
                warnings.append({"source":src,"code":"EMPTY_OWNER_COLLECTION","message":"Organization owner inventory is empty; validate token visibility and organization membership before treating owner_count=0 as authoritative."})
    if any(x.get("code")=="FIELD_UNAVAILABLE" for x in warnings):
        status="FIELD_INCOMPLETE"
    elif any(x.get("code")=="ENDPOINT_UNAVAILABLE" for x in warnings):
        status="WARNING"
    elif warnings:
        status="WARNING"
    elif assessment_status == "NOT ASSESSED":
        # Evidence is complete, but the evaluator explicitly requires an
        # organization-defined policy, process, convention, or external
        # governance artifact. This is not an evidence collection failure.
        status="POLICY_REQUIRED"
    else:
        status="OK"
    return {"status":status,"warnings":warnings,"field_states":states}

def ok(x): return isinstance(x,dict) and x.get("status")==200

def getv(obj,*path):
    cur=obj
    for p in path:
        if isinstance(cur,dict) and p in cur: cur=cur[p]
        else: return None
    return cur

def count(data):
    return len(data.get("items",[])) if isinstance(data,dict) else 0

def repo_items(ev):
    return ev.get("repositories",{}).get("items",[])

def repo_data(ev,full,key):
    return getv(ev.get("repository_evidence",{}).get(full,{}).get(key,{}),"data")

def workflow_files(ev,full):
    w=repo_data(ev,full,"workflow_files")
    if isinstance(w,dict): return w.get("items",[])
    return []

def file_text(ev,full,path):
    d=ev.get("repository_evidence",{}).get(full,{}).get("files",{}).get(path)
    if not d or d.get("status")!=200: return None
    data=d.get("data")
    if isinstance(data,dict) and data.get("encoding")=="base64":
        import base64
        try: return base64.b64decode(data["content"]).decode("utf-8","replace")
        except: return None
    return data if isinstance(data,str) else None

def aggregate_repo_control(ev, predicate):
    repos=repo_items(ev)
    if not repos: return "NOT ASSESSED", "No repository inventory evidence."
    eligible=[r for r in repos if not r.get("archived",False)]
    if not eligible: return "N/A","No active repositories."
    states=[predicate(r) for r in eligible]
    if all(s is True for s in states): return "PASS",f"{len(eligible)}/{len(eligible)} repositories satisfy the control."
    if any(s is True for s in states): return "PARTIAL",f"{sum(s is True for s in states)}/{len(eligible)} repositories satisfy the control."
    return "FAIL",f"0/{len(eligible)} repositories satisfy the control."

def rules_for(ev,full):
    x=repo_data(ev,full,"rulesets")
    if isinstance(x,list):
        return x
    if isinstance(x,dict):
        if isinstance(x.get("rulesets"),list): return x["rulesets"]
        if isinstance(x.get("data"),list): return x["data"]
        if isinstance(x.get("data"),dict): return x["data"].get("rulesets",[])
    return []

def all_rulesets(ev,full):
    return rules_for(ev,full)

def active_rules_for_default_branch(ev,full):
    d=ev.get("repository_evidence",{}).get(full,{})
    x=d.get("default_branch_rules",{})
    if x.get("status") != 200:
        return []
    data=x.get("data")
    return data if isinstance(data,list) else []

def merged_rules(ev,full):
    local = rules_for(ev,full)
    branch = active_rules_for_default_branch(ev,full)
    return branch if branch else local

def rule_types(rules):
    return {x.get("type") for r in rules if isinstance(r,dict) for x in r.get("rules",[])}

def has_rule(rules,*types):
    rt=rule_types(rules)
    return any(t in rt for t in types)

def effective_rules(ev,full):
    # Repository endpoint may return repository-local rulesets. Organization
    # rulesets are separately evaluated for coverage.
    return rules_for(ev,full)

def parse_actions_yaml(text):
    if not text: return {}
    # Lightweight parser intentionally avoids PyYAML dependency.
    out={"uses":[],"permissions":[],"environments":[],"concurrency":False,"retention":False}
    out["uses"]=re.findall(r'(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)',text)
    out["permissions"]=re.findall(r'(?m)^\s*permissions:\s*(?:#.*)?$',text)
    out["environments"]=re.findall(r'(?m)environment:\s*([A-Za-z0-9_.-]+)',text)
    out["concurrency"]=bool(re.search(r'(?m)^\s*concurrency\s*:',text))
    out["retention"]=bool(re.search(r'(?m)retention-days\s*:',text))
    return out

def _source_coverage(ev, source, repo_names):
    source=source or ""
    if source.startswith("Manual") or source.startswith("SCIM"):
        return {"source":source,"population":1,"available":0,"unavailable":1,"coverage_ratio":0.0,"gaps":[source]}
    entry=source_registry_entry(source)
    if entry and entry.get("scope")=="org":
        item=ev.get(entry["key"],{})
        available=1 if item.get("evidence",{}).get("availability")=="AVAILABLE" or item.get("status")==200 else 0
        # Repository inventory is a population source: expose one row per
        # repository so downstream coverage remains meaningful.
        if entry["key"]=="repositories":
            total=len(item.get("items",[])) if available else 1
            return {"source":source,"population":total,"available":total if available else 0,"unavailable":0 if available else total,"coverage_ratio":1.0 if available else 0.0,"gaps":[] if available else repo_names[:50]}
        return {"source":source,"population":1,"available":available,"unavailable":1-available,"coverage_ratio":float(available),"gaps":[] if available else [source]}
    if "GET /orgs/{org}/repos" in source:
        item=ev.get("repositories",{}); available=1 if item.get("status")==200 else 0; total=len(repo_names) if repo_names else (len(item.get("items",[])) if available else 1)
        return {"source":source,"population":total,"available":total if available else 0,"unavailable":0 if available else total,"coverage_ratio":1.0 if available else 0.0,"gaps":[] if available else repo_names[:50]}
    if source.startswith("GET /repos/{owner}/{repo}"):
        key_map={"/rulesets":"rulesets","/environments":"environments","/collaborators":"collaborators","/actions/workflows":"workflows","/code-scanning/analyses":"code_scanning","/secret-scanning/alerts":"secret_scanning","/dependabot/alerts":"dependabot","/contents/":"files","/rules/branches/":"default_branch_rules"}; key=next((v for k,v in key_map.items() if k in source),"repo")
        good=0; gaps=[]
        for name in repo_names:
            d=ev.get("repository_evidence",{}).get(name,{})
            if key=="files":
                vals=d.get("files",{}).values() if isinstance(d.get("files"),dict) else []
                available=any(isinstance(v,dict) and (v.get("evidence",{}).get("availability")=="AVAILABLE" or v.get("status")==200) for v in vals)
            else:
                item=d.get(key,{})
                available=isinstance(item,dict) and (item.get("evidence",{}).get("availability")=="AVAILABLE" or item.get("status")==200)
            if available: good+=1
            else: gaps.append(name)
        total=len(repo_names)
        return {"source":source,"population":total,"available":good,"unavailable":total-good,"coverage_ratio":good/total if total else None,"gaps":gaps[:50]}
    return {"source":source,"population":1,"available":0,"unavailable":1,"coverage_ratio":0.0,"gaps":[source]}

def evidence_coverage(ev, repo_names, evidence_sources=None, evidence_keys=None):
    if evidence_sources is None:
        evidence_sources=[f"GET /repos/{{owner}}/{{repo}}/{k}" for k in (evidence_keys or ["repo"])]
    sources=[_source_coverage(ev,s,repo_names) for s in evidence_sources if s]
    ratios=[s["coverage_ratio"] for s in sources if s["coverage_ratio"] is not None]
    # Evidence sources can be alternatives (for example organization rulesets
    # vs repository-scoped rulesets). Do not penalize an available fallback by
    # taking the minimum ratio across mutually exclusive sources. Preserve the
    # per-source availability and expose an aggregate union ratio.
    if len(sources) > 1 and any("rulesets" in (s.get("source") or "") for s in sources):
        available=max(s["available"] for s in sources)
        population=max(s["population"] for s in sources)
        aggregate_ratio=(available/population) if population else None
    else:
        available=sum(s["available"] for s in sources)
        population=sum(s["population"] for s in sources)
        aggregate_ratio=min(ratios) if ratios else None
    return {"population":population,"available":available,"unavailable":max(0,population-available),"coverage_ratio":aggregate_ratio,"gaps":[g for s in sources for g in s.get("gaps",[])][:50],"sources":sources}

def evidence_confidence(status, coverage, manual=False):
    if manual: return "MANUAL"
    if status in ("NOT ASSESSED","N/A"): return "LOW"
    ratio=coverage.get("coverage_ratio")
    if ratio is None: return "MEDIUM"
    if ratio >= 0.99: return "HIGH"
    if ratio >= 0.90: return "MEDIUM"
    return "LOW"

def evidence_confidence_with_quality(status, coverage, manual=False, quality=None):
    base=evidence_confidence(status,coverage,manual)
    if manual or not quality or quality.get("status") == "OK":
        return base
    # Field-level incompleteness is stronger than a generic structural warning:
    # a 100% HTTP coverage ratio does not imply the required attributes are usable.
    if quality.get("status") == "FIELD_INCOMPLETE":
        return "LOW"
    if quality.get("status") == "POLICY_REQUIRED":
        ratio=coverage.get("coverage_ratio")
        return "HIGH" if ratio is not None and ratio >= 0.99 else ("MEDIUM" if ratio is not None and ratio >= 0.90 else "LOW")
    if base == "HIGH":
        return "MEDIUM"
    if base == "MEDIUM":
        return "LOW"
    return base

def repository_rulesets(ev):
    """Return unique rulesets visible through repository-level read-only APIs."""
    out={}
    for full,d in ev.get("repository_evidence",{}).items():
        data=d.get("rulesets",{}).get("data") if isinstance(d,dict) else None
        items=data if isinstance(data,list) else (data.get("rulesets",[]) if isinstance(data,dict) else [])
        for item in items:
            if not isinstance(item,dict):
                continue
            rid=item.get("id")
            if rid is None:
                continue
            x=dict(item); x["_repository"]=full
            out[str(rid)]=x
    return list(out.values())

def organization_rulesets_from_repository_evidence(ev):
    return [x for x in repository_rulesets(ev) if x.get("source_type") == "Organization"]

