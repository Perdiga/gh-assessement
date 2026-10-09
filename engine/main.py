#!/usr/bin/env python3
"""
GitHub Enterprise Assessment Framework Engine v1.8.1
READ-ONLY assessment.

Architecture:
  collectors -> normalized evidence -> control adapters -> findings

Every one of the 132 catalog controls has an evaluator adapter. Controls
that require business/manual evidence return NOT ASSESSED until that evidence
is supplied; they are never silently converted into PASS/FAIL.

Usage:
  export GITHUB_APP_ID="123456"
  export GITHUB_APP_PRIVATE_KEY_FILE="assessment-app.private-key.pem"
    python main.py --org my-org \
            --catalog ../catalogs/latest/github_controls.json \
      --out assessment

Optional:
  --manual-evidence manual_evidence.json
  --inactive-days 180

Manual evidence example:
{
  "ORG-007": {"status":"PASS","reason":"All external users have approved tickets."},
  "DR-006": {"status":"PASS","reason":"Quarterly recovery exercise completed 2026-09-15."}
}
"""
import argparse
import csv
import json
import logging
import os
import ssl
from dotenv import load_dotenv
from collector import collect
from github_client import (
    API_VERSION,
    AUTHENTICATION_VERSION,
    AssessmentEnvironmentError,
    GitHubAppAuthenticator,
    check_runtime,
    load_private_key,
)

from assessment import (
    ENGINE_VERSION,
    PERMISSION_MANIFEST_VERSION,
    SEVERITY_WEIGHT,
    STATUSES,
    STATUS_SCORE,
    assess,
    assessment_blocker,
)
from evidence import (
    evidence_confidence_with_quality,
    evidence_coverage,
    evidence_quality_for_control,
    ok,
    permission_audit,
    permission_requirements,
    repo_items,
)

from reporting import (
    authentication_manifest,
    build_control_permission_matrix,
    write_markdown_report,
)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

DEFAULT_CATALOG = os.path.join(PROJECT_ROOT, "catalogs", "latest", "github_controls.json")
LOG = logging.getLogger("github_assessment")





def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org")
    parser.add_argument(
        "--catalog",
        default=DEFAULT_CATALOG,
        help="Control catalog JSON (defaults to catalogs/latest/github_controls.json).",
    )
    parser.add_argument("--out", default="github_assessment_output")
    parser.add_argument("--manual-evidence", default=None)
    parser.add_argument("--inactive-days", type=int, default=180)
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="Validate the Python/TLS runtime and exit.",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Console log level (default: INFO).",
    )
    parser.add_argument(
        "--github-app-id",
        default=os.getenv("GITHUB_APP_ID"),
        help="GitHub App ID (or GITHUB_APP_ID).",
    )
    parser.add_argument(
        "--github-app-private-key-file",
        default=os.getenv("GITHUB_APP_PRIVATE_KEY_FILE"),
        help="Path to GitHub App private key PEM (or GITHUB_APP_PRIVATE_KEY_FILE).",
    )
    parser.add_argument(
        "--github-app-private-key",
        default=os.getenv("GITHUB_APP_PRIVATE_KEY"),
        help="GitHub App private key PEM/base64 (or GITHUB_APP_PRIVATE_KEY).",
    )
    parser.add_argument(
        "--github-installation-id",
        default=os.getenv("GITHUB_APP_INSTALLATION_ID"),
        help="Optional installation ID; otherwise resolve from the organization.",
    )
    parser.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN"),
        help="Legacy PAT/fine-grained token fallback (or GITHUB_TOKEN).",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        check_runtime()
    except AssessmentEnvironmentError as exc:
        raise SystemExit(f"ERROR: {exc}")

    if args.self_check:
        print(f"PASS: Python TLS runtime is compatible: {ssl.OPENSSL_VERSION}")
        return

    if not args.org:
        raise SystemExit("--org is required unless --self-check is used")

    with open(args.catalog,encoding="utf-8") as f: catalog=json.load(f)

    auth_metadata=None
    if args.github_app_id and (args.github_app_private_key_file or args.github_app_private_key):
        private_key=load_private_key(args.github_app_private_key,args.github_app_private_key_file)
        try:
            token,auth_metadata=GitHubAppAuthenticator(args.github_app_id,private_key,args.github_installation_id).authenticate(args.org)
            LOG.info("Authentication: GitHub App installation=%s permissions=%s expires_at=%s",auth_metadata["installation_id"],auth_metadata["permissions"],auth_metadata["expires_at"])
        except Exception as exc:
            raise SystemExit(f"GitHub App authentication failed: {exc}")
    elif args.github_token:
        token=args.github_token
        auth_metadata={"type":"token","token_source":"GITHUB_TOKEN","legacy_fallback":True,"authentication_version":AUTHENTICATION_VERSION}
        LOG.warning("Authentication: using legacy token fallback. Prefer GitHub App installation authentication for production assessments.")
    else:
        raise SystemExit("GitHub App credentials are required: --github-app-id plus --github-app-private-key-file/--github-app-private-key (or use GITHUB_TOKEN as a legacy fallback)")
    manual={}
    if args.manual_evidence:
        with open(args.manual_evidence,encoding="utf-8") as f: manual=json.load(f)

    os.makedirs(args.out,exist_ok=True)
    LOG.info("Starting assessment: org=%s output=%s", args.org, os.path.abspath(args.out))
    LOG.info("Phase 1/3: collecting GitHub evidence")
    evidence=collect(token,args.org,auth_metadata)
    LOG.info("Phase 2/3: writing raw evidence")
    with open(os.path.join(args.out,"raw_evidence.json"),"w",encoding="utf-8") as f:
        json.dump(evidence,f,indent=2,ensure_ascii=False)

    with open(os.path.join(args.out,"control_permission_matrix.json"),"w",encoding="utf-8") as f:
        json.dump(build_control_permission_matrix(catalog),f,indent=2,ensure_ascii=False)
    with open(os.path.join(args.out,"authentication_manifest.json"),"w",encoding="utf-8") as f:
        json.dump(authentication_manifest(auth_metadata,catalog),f,indent=2,ensure_ascii=False)
    auth_permission_audit=permission_audit(auth_metadata,catalog)
    with open(os.path.join(args.out,"permission_audit.json"),"w",encoding="utf-8") as f:
        json.dump(auth_permission_audit,f,indent=2,ensure_ascii=False)

    findings=[]
    LOG.info("Phase 3/3: evaluating %s controls", len(catalog["controls"]))
    for i,c in enumerate(catalog["controls"],1):
        status,reason=assess(c,evidence,manual,args)
        if status not in STATUSES: status="NOT ASSESSED"; reason=f"Invalid evaluator result: {reason}"
        repo_population=[r["full_name"] for r in repo_items(evidence) if not r.get("archived",False)]
        evidence_sources=[x.get("source") for x in c.get("evidence",[]) if x.get("source")]
        coverage=evidence_coverage(evidence,repo_population,evidence_sources=evidence_sources)
        quality=evidence_quality_for_control(c,evidence,assessment_status=status,assessment_reason=reason)
        blocker=assessment_blocker(c,evidence,status,reason,quality,c["control_id"] in manual)
        field_states=quality.get("field_states",[])
        for src in coverage.get("sources",[]):
            matching=[x for x in field_states if x.get("source")==src.get("source")]
            if matching:
                src["field_states"]=matching
                src["availability"]="AVAILABLE" if all(x.get("availability")=="AVAILABLE" for x in matching) else matching[0].get("availability")
            else:
                src["availability"]="AVAILABLE" if src.get("available") else "ENDPOINT_UNAVAILABLE"
            src["required_permissions"]=permission_requirements(src.get("source"))
            src["accepted_github_permissions"]=[]
            src["granted_app_permissions"]={}
            # X-Accepted-GitHub-Permissions describes what the endpoint accepts,
            # not what the current installation token was granted. Keep the two
            # concepts separate to avoid false permission-escalation evidence.
            source=src.get("source","")
            if source == "GET /orgs/{org}":
                src["accepted_github_permissions"]=evidence.get("organization",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/members?role=admin":
                src["accepted_github_permissions"]=evidence.get("owners",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/members":
                src["accepted_github_permissions"]=evidence.get("members",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/outside-collaborators":
                src["accepted_github_permissions"]=evidence.get("outside_collaborators",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/teams":
                src["accepted_github_permissions"]=evidence.get("teams",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/rulesets":
                src["accepted_github_permissions"]=evidence.get("org_rulesets",{}).get("accepted_github_permissions",[])
            elif source == "GET /orgs/{org}/audit-log":
                src["accepted_github_permissions"]=evidence.get("audit_log",{}).get("accepted_github_permissions",[])
            elif source.startswith("GET /repos/{owner}/{repo}"):
                # Repository endpoint permissions are captured per repository.
                vals=[]
                for rn in repo_population:
                    d=evidence.get("repository_evidence",{}).get(rn,{})
                    for k,v in d.items():
                        if isinstance(v,dict) and v.get("accepted_github_permissions"):
                            vals.extend(v.get("accepted_github_permissions",[]))
                src["accepted_github_permissions"]=sorted(set(vals))
            granted=(auth_metadata or {}).get("permissions",{}) if isinstance(auth_metadata,dict) else {}
            src["granted_app_permissions"]={k:v for k,v in sorted(granted.items())}
        if i == 1 or i % 25 == 0 or i == len(catalog["controls"]):
            LOG.info("Evaluation progress: %s/%s controls", i, len(catalog["controls"]))
        evidence_semantics={}
        if c["control_id"]=="SEC-080":
            raw=evidence.get("attestation_repositories",{})
            evidence_semantics={"technical_evidence":"AVAILABLE" if raw.get("status")==200 else "UNAVAILABLE","governance_evidence":"REQUIRED","process_evidence":"REQUIRED"}
        elif c["control_id"]=="SEC-081":
            cs=evidence.get("org_code_scanning_alerts",{}); ss=evidence.get("org_secret_scanning_alerts",{})
            evidence_semantics={
                "technical_evidence":"AVAILABLE" if cs.get("status")==200 or ss.get("status")==200 else "UNAVAILABLE",
                "governance_evidence":"MISSING",
                "process_evidence":"MISSING"
            }
        findings.append({
            "control_id":c["control_id"],"domain":c["domain"],"title":c["title"],
            "severity":c["severity"],"status":status,"reason":reason,
            "well_architected_mapping":c.get("well_architected_mapping",[]),
            "automated": c["control_id"] not in manual,
            "evidence_semantics": evidence_semantics,
            "evidence_sources":[x.get("source") for x in c.get("evidence",[])],
            "assessment_blocker":blocker,
            "evidence_provenance":{
                "sources":c.get("evidence",[]),
                "collected_at":evidence.get("metadata",{}).get("collected_at"),
                "coverage":coverage,
                "confidence":evidence_confidence_with_quality(status,coverage,c["control_id"] in manual,quality),
                "quality":quality
            }
        })

    # Domain scoring excludes NOT ASSESSED/N/A/INFO from denominator.
    domains={}
    for f in findings:
        d=domains.setdefault(f["domain"],{"total":0,"scored":0,"pass":0,"partial":0,"fail":0,"not_assessed":0})
        d["total"]+=1
        s=f["status"]
        if s in STATUS_SCORE:
            d["scored"]+=1; d[{"PASS":"pass","PARTIAL":"partial","FAIL":"fail"}[s]]+=1
        elif s=="NOT ASSESSED": d["not_assessed"]+=1
    for d in domains.values():
        d["score"]=round((d["pass"]+0.5*d["partial"])/d["scored"]*100,1) if d["scored"] else None

    scored=[f for f in findings if f["status"] in STATUS_SCORE]
    overall=round(sum(STATUS_SCORE[f["status"]] for f in scored)/len(scored)*100,1) if scored else None
    weighted=sum(SEVERITY_WEIGHT[f["severity"]] for f in findings if f["status"]=="FAIL")
    critical_fail=sum(1 for f in findings if f["status"]=="FAIL" and f["severity"]=="critical")
    blocker_counts={}
    blocker_resolution_counts={}
    for f in findings:
        b=f.get("assessment_blocker")
        if b:
            category=b.get("category","UNKNOWN")
            blocker_counts[category]=blocker_counts.get(category,0)+1
            resolution=b.get("resolution","UNKNOWN")
            blocker_resolution_counts[resolution]=blocker_resolution_counts.get(resolution,0)+1

    result={"metadata":{**evidence["metadata"],"engine_version":ENGINE_VERSION},
            "assessment_security":{"permission_audit_status":auth_permission_audit.get("status"),"unnecessary_write_permissions":auth_permission_audit.get("unnecessary_write_permissions",[]),"elevated_permissions":auth_permission_audit.get("elevated_permissions",[])},
            "summary":{"controls":len(findings),"overall_score":overall,
                       "scored_controls":len(scored),"not_assessed":sum(f["status"]=="NOT ASSESSED" for f in findings),
                       "failures":sum(f["status"]=="FAIL" for f in findings),
                       "critical_failures":critical_fail,"risk_weight":weighted,"not_assessed_blockers":blocker_counts,"blocker_resolutions":blocker_resolution_counts},
            "domains":domains,"findings":findings}
    with open(os.path.join(args.out,"findings.json"),"w",encoding="utf-8") as f:
        json.dump(result,f,indent=2,ensure_ascii=False)

    confidence_counts={}
    for f in findings:
        c=f.get("evidence_provenance",{}).get("confidence","UNKNOWN")
        confidence_counts[c]=confidence_counts.get(c,0)+1
    provenance={"assessment":{
        "framework_version":catalog.get("version"),
        "organization":evidence.get("metadata",{}).get("org"),
        "collected_at":evidence.get("metadata",{}).get("collected_at")},
        "confidence_counts":confidence_counts,
        "not_assessed_blockers":blocker_counts,
        "blocker_resolutions":blocker_resolution_counts,
        "controls":[{"control_id":f["control_id"],"status":f["status"],
                     "assessment_blocker":f.get("assessment_blocker"),
                     "confidence":f.get("evidence_provenance",{}).get("confidence"),
                     "coverage":f.get("evidence_provenance",{}).get("coverage"),
                     "sources":f.get("evidence_provenance",{}).get("sources",[])}
                    for f in findings]}
    with open(os.path.join(args.out,"evidence_provenance.json"),"w",encoding="utf-8") as f:
        json.dump(provenance,f,indent=2,ensure_ascii=False)

    permission_manifest={"version":PERMISSION_MANIFEST_VERSION,"api_version":API_VERSION,"authentication":auth_metadata or {"type":"token"},"controls":{}}
    for c in catalog["controls"]:
        permission_manifest["controls"][c["control_id"]]={
            "sources":[{
                "source":e.get("source"),
                "required_permissions":permission_requirements(e.get("source")),
                "fields":e.get("field"),
                "key":e.get("key")
            } for e in c.get("evidence",[]) if e.get("source")],
        }
    with open(os.path.join(args.out,"permission_manifest.json"),"w",encoding="utf-8") as f:
        json.dump(permission_manifest,f,indent=2,ensure_ascii=False)

    with open(os.path.join(args.out,"summary.csv"),"w",newline="",encoding="utf-8") as f:
        fields=["control_id","domain","title","well_architected_stage","severity","status","assessment_blocker","blocker_resolution","blocker_action","blocker_detail","reason","automated","well_architected_mapping","confidence","coverage"]
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for x in findings:
            y=dict(x); y["well_architected_stage"]=next((c.get("well_architected_stage") for c in catalog["controls"] if c.get("control_id")==x.get("control_id")), "—"); y["well_architected_mapping"]="; ".join(x["well_architected_mapping"]); y["confidence"]=x.get("evidence_provenance",{}).get("confidence"); y["coverage"]=x.get("evidence_provenance",{}).get("coverage",{}).get("coverage_ratio"); b=x.get("assessment_blocker") or {}; y["assessment_blocker"]=b.get("category"); y["blocker_resolution"]=b.get("resolution"); y["blocker_action"]=b.get("recommended_action"); y["blocker_detail"]=b.get("detail"); w.writerow({k:y.get(k) for k in fields})

    write_markdown_report(
        args, catalog, findings, domains, scored, overall, critical_fail,
        auth_permission_audit, auth_metadata, evidence, result,
    )

    LOG.info("Assessment complete. Outputs written to %s", os.path.abspath(args.out))
    print(json.dumps(result["summary"],indent=2))
    print(f"Outputs written to {args.out}/")

if __name__=="__main__":
    main()
