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
import argparse, csv, json, logging, os, re, ssl, sys, time, base64
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

API="https://api.github.com"
API_VERSION="2026-03-10"
DEFAULT_CATALOG=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "catalogs", "latest", "github_controls.json"))
LOG=logging.getLogger("github_assessment")
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


class AssessmentEnvironmentError(RuntimeError):
    """Raised when the local Python runtime is incompatible with urllib3."""


def check_runtime() -> None:
    """Validate the TLS runtime before importing requests/urllib3."""
    version = ssl.OPENSSL_VERSION

    if "LibreSSL" in version:
        raise AssessmentEnvironmentError(
            f"Unsupported TLS runtime: {version}. urllib3 v2 requires "
            "OpenSSL 1.1.1+. Install a modern CPython linked to OpenSSL "
            "(for example, Homebrew Python) and recreate the virtual environment."
        )

    match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise AssessmentEnvironmentError(
            f"Unable to verify OpenSSL from ssl.OPENSSL_VERSION={version!r}."
        )

    version_tuple = tuple(map(int, match.groups()))
    if version_tuple < (1, 1, 1):
        raise AssessmentEnvironmentError(
            f"Unsupported OpenSSL version: {version}. urllib3 v2 requires OpenSSL 1.1.1+."
        )


class GH:
    def __init__(self, token, auth_metadata=None):
        check_runtime()
        import requests

        self.s = requests.Session()
        self.auth_metadata = auth_metadata or {"type":"token"}
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "github-enterprise-assessment-framework/1.8.1"
        })

    def get(self, path, params=None):
        url = path if path.startswith("http") else API + path
        # GitHub content lookups legitimately return 404 for optional files
        # (e.g. CODEOWNERS/SECURITY.md). Network disconnects are different:
        # they are transient collection failures and must not abort the run.
        last_error = None
        for attempt in range(1, 7):
            try:
                r = self.s.get(url, params=params, timeout=45)
            except Exception as exc:
                last_error = exc
                if attempt >= 6:
                    LOG.error("GET %s failed after %s attempts: %s", path, attempt, exc)
                    raise
                delay = min(30, 2 ** (attempt - 1))
                LOG.warning("GET %s connection error (%s); retrying in %ss [attempt %s/6]", path, exc, delay, attempt)
                time.sleep(delay)
                continue

            if r.status_code == 429 or (
                r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0"
            ):
                retry = int(r.headers.get("Retry-After", "0") or 0)
                if not retry:
                    reset = int(r.headers.get("X-RateLimit-Reset", "0") or 0)
                    retry = max(1, min(60, reset - int(time.time())))
                LOG.warning("Rate limited: retrying in %ss", retry)
                time.sleep(retry)
                continue

            if r.status_code in (502, 503, 504, 520, 522, 524) and attempt < 6:
                delay = min(30, 2 ** (attempt - 1))
                LOG.warning("GET %s -> HTTP %s; retrying in %ss [attempt %s/6]", path, r.status_code, delay, attempt)
                time.sleep(delay)
                continue

            if r.status_code >= 400 and r.status_code != 404:
                LOG.warning("GET %s -> HTTP %s", path if path.startswith("/") else url, r.status_code)
            elif r.status_code == 404:
                LOG.debug("GET %s -> HTTP 404 (resource/file not found or inaccessible)", path)
            return r
        raise RuntimeError(f"GET failed without response: {path}; last_error={last_error}")

    @staticmethod
    def _next_link(response):
        link = response.headers.get("Link", "")
        for entry in link.split(","):
            match = re.search(r'<([^>]+)>;\s*rel="next"', entry)
            if match:
                return match.group(1)
        return None

    def page(self, path, params=None):
        """Follow GitHub REST API Link headers for pagination."""
        items = []
        url = path if path.startswith("http") else API + path
        first = True

        while url:
            response = self.get(url, params if first else None)
            first = False

            if response.status_code != 200:
                return {
                    "status": response.status_code,
                    "items": items,
                    "error": response.text[:500],
                    "evidence": {"availability": classify_http(response.status_code, body(response), response.text[:500])[0],
                                 "reason": classify_http(response.status_code, body(response), response.text[:500])[1]},
                    "accepted_github_permissions": observed_permissions(response),
                }

            data = response.json()
            if not isinstance(data, list):
                return {"status": 200, "data": data, "items": items, "accepted_github_permissions": observed_permissions(response)}

            items.extend(data)
            url = self._next_link(response)

        return {"status": 200, "items": items, "accepted_github_permissions": observed_permissions(response)}


class GitHubAppAuthenticator:
    """Create short-lived installation credentials for a GitHub App."""
    def __init__(self, app_id, private_key, installation_id=None):
        check_runtime()
        import requests
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("PyJWT is required for GitHub App authentication; install project dependencies.") from exc
        self.app_id = str(app_id)
        self.private_key = private_key
        self.installation_id = int(installation_id) if installation_id else None
        self.jwt = jwt
        self.s = requests.Session()
        self.s.headers.update({"Accept":"application/vnd.github+json","X-GitHub-Api-Version":API_VERSION,"User-Agent":"github-enterprise-assessment-framework/1.8.1"})

    def app_jwt(self):
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self.app_id}
        return self.jwt.encode(payload, self.private_key, algorithm="RS256")

    def _request(self, method, path, **kwargs):
        url = path if path.startswith("http") else API + path
        response = self.s.request(method, url, timeout=45, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub App authentication request failed: HTTP {response.status_code}: {response.text[:500]}")
        return response

    def resolve_installation(self, org):
        if self.installation_id:
            return self.installation_id
        r = self._request("GET", f"/orgs/{org}/installation", headers={"Authorization": f"Bearer {self.app_jwt()}"})
        self.installation_id = int(r.json()["id"])
        return self.installation_id

    def authenticate(self, org):
        installation_id = self.resolve_installation(org)
        r = self._request("POST", f"/app/installations/{installation_id}/access_tokens", headers={"Authorization": f"Bearer {self.app_jwt()}"})
        data = r.json()
        repositories = data.get("repositories")
        metadata = {
            "type":"github_app_installation",
            "app_id":int(self.app_id) if self.app_id.isdigit() else self.app_id,
            "installation_id":installation_id,
            "organization":org,
            "permissions":data.get("permissions",{}),
            "repository_count":len(repositories) if isinstance(repositories,list) else None,
            "repository_selection":"scoped" if isinstance(repositories,list) else "installation_default",
            "expires_at":data.get("expires_at"),
            "authentication_version":AUTHENTICATION_VERSION,
        }
        return data["token"], metadata


def load_private_key(value=None, path=None):
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read()
    if value:
        if "BEGIN" in value:
            return value.replace("\\n", "\n")
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            if "BEGIN" in decoded:
                return decoded
        except Exception:
            pass
        return value
    return None

def body(r):
    try: return r.json()
    except Exception: return None

PERMISSION_MANIFEST_VERSION = "1.3"
AUTHENTICATION_VERSION = "1.1"
ENGINE_VERSION = "1.8.1"

# Canonical evidence-source registry. Each catalog source maps to the exact
# raw-evidence location used by collection and provenance resolution.
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

def observed_permissions(response):
    raw = response.headers.get("X-Accepted-GitHub-Permissions", "")
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]

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
            candidates=[files.get(p) for p in candidate_paths if isinstance(files,dict) and isinstance(files.get(p),dict)]
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

def classify_http(status, data=None, text=""):
    message = str(data.get("message", "")) if isinstance(data, dict) else ""
    message = f"{message} {text or ''}".lower()
    if status == 200: return "AVAILABLE", "ok"
    if status in (401, 403) and any(x in message for x in ("resource not accessible", "forbidden", "bad credentials", "authentication")):
        return "UNAVAILABLE", "permission_denied"
    if status in (403, 404) and any(x in message for x in ("advanced security must be enabled", "must be enabled", "secret scanning is disabled", "disabled on this repository")):
        return "AVAILABLE", "feature_disabled"
    if status == 429: return "UNAVAILABLE", "rate_limited"
    if status >= 500: return "UNAVAILABLE", "server_error"
    if status in (401, 403): return "UNAVAILABLE", "access_denied"
    if status == 404: return "UNAVAILABLE", "not_found_or_inaccessible"
    if status >= 400: return "UNAVAILABLE", "http_error"
    return "UNAVAILABLE", "unknown"

def ok(x): return isinstance(x,dict) and x.get("status")==200

def api_result(r):
    data=body(r) if r.headers.get("content-type","").startswith("application/json") else r.text[:1000]
    availability,reason=classify_http(r.status_code,data,r.text[:1000])
    return {"status":r.status_code,"data":data,"evidence":{"availability":availability,"reason":reason},"accepted_github_permissions":observed_permissions(r)}

def ruleset_diagnostic(response, path, params=None):
    """Capture safe diagnostic metadata for ruleset access without response bodies or secrets."""
    data=body(response)
    items=data if isinstance(data,list) else (data.get("rulesets",[]) if isinstance(data,dict) else [])
    return {
        "path": path,
        "params": params or {},
        "http_status": response.status_code,
        "accepted_github_permissions": observed_permissions(response),
        "oauth_scopes": response.headers.get("X-OAuth-Scopes", ""),
        "accepted_github_permissions_header": response.headers.get("X-Accepted-GitHub-Permissions", ""),
        "item_count": len(items) if isinstance(items,list) else None,
        "source_type_counts": ({k: sum(1 for x in items if isinstance(x,dict) and x.get("source_type")==k) for k in sorted({x.get("source_type") for x in items if isinstance(x,dict) and x.get("source_type")})} if isinstance(items,list) else {}),
        "evidence": classify_http(response.status_code, data, response.text[:1000]),
    }

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

def collect(token,org,auth_metadata=None):
    started=time.monotonic()
    gh=GH(token,auth_metadata); stamp=datetime.now(timezone.utc).isoformat()
    LOG.info("Assessment collection started: organization=%s API=%s", org, API_VERSION)
    e={"metadata":{"org":org,"collected_at":stamp,"api_version":API_VERSION,"authentication":auth_metadata or {"type":"token"}},
       "organization":{}, "members":{}, "owners":{}, "outside_collaborators":{},
       "teams":{}, "repositories":{}, "org_rulesets":{}, "audit_log":{}}

    def one(key,path,params=None):
        LOG.info("[ORG] %s -> GET %s", key, path)
        e[key]=api_result(gh.get(path,params))
        LOG.info("[ORG] %s -> HTTP %s (%.1fs)", key, e[key].get("status"), time.monotonic()-started)
    def many(key,path,params=None):
        LOG.info("[ORG] %s -> GET %s (paginated)", key, path)
        e[key]=gh.page(path,params)
        LOG.info("[ORG] %s -> HTTP %s, items=%s (%.1fs)", key, e[key].get("status"), len(e[key].get("items",[])), time.monotonic()-started)

    one("organization",f"/orgs/{org}")
    many("members",f"/orgs/{org}/members")
    many("owners",f"/orgs/{org}/members",{"role":"admin"})
    many("outside_collaborators",f"/orgs/{org}/outside-collaborators")
    many("teams",f"/orgs/{org}/teams")
    many("repositories",f"/orgs/{org}/repos",{"type":"all","sort":"full_name"})
    LOG.info("[ORG] org_rulesets -> GET /orgs/%s/rulesets (paginated)", org)
    e["org_rulesets"] = gh.page(f"/orgs/{org}/rulesets")
    e["org_rulesets_diagnostic"] = {
        "path": f"/orgs/{org}/rulesets",
        "http_status": e["org_rulesets"].get("status"),
        "accepted_github_permissions": e["org_rulesets"].get("accepted_github_permissions",[]),
        "item_count": len(e["org_rulesets"].get("items",[])),
        "source_type_counts": {},
        "evidence": e["org_rulesets"].get("evidence",{}),
    }
    one("actions_permissions",f"/orgs/{org}/actions/permissions")
    one("actions_selected",f"/orgs/{org}/actions/permissions/selected-actions")
    one("actions_workflow_permissions",f"/orgs/{org}/actions/permissions/workflow")
    one("self_hosted_runner_policy",f"/orgs/{org}/actions/permissions/self-hosted-runners")
    many("runner_groups",f"/orgs/{org}/actions/runner-groups")
    one("audit_log",f"/orgs/{org}/audit-log",{"per_page":100})
    many("attestation_repositories",f"/orgs/{org}/attestations/repositories")
    many("org_code_scanning_alerts",f"/orgs/{org}/code-scanning/alerts")
    many("org_secret_scanning_alerts",f"/orgs/{org}/secret-scanning/alerts")
    one("scim_users",f"/scim/v2/organizations/{org}/Users",{"startIndex":1,"count":100})

    repos=e["repositories"].get("items",[])
    LOG.info("Repository evidence phase: %s repositories discovered", len(repos))
    e["repository_evidence"]={}
    for idx,r in enumerate(repos,1):
        full=r["full_name"]; owner,name=full.split("/",1)
        repo_started=time.monotonic()
        LOG.info("[REPO %s/%s] START %s", idx, len(repos), full)
        d={"repo":api_result(gh.get(f"/repos/{owner}/{name}"))}
        for key,path in {
            "rulesets":f"/repos/{owner}/{name}/rulesets",
            "environments":f"/repos/{owner}/{name}/environments",
            "collaborators":f"/repos/{owner}/{name}/collaborators",
            "workflows":f"/repos/{owner}/{name}/actions/workflows",
            "code_scanning":f"/repos/{owner}/{name}/code-scanning/analyses",
            "secret_scanning":f"/repos/{owner}/{name}/secret-scanning/alerts",
            "dependabot":f"/repos/{owner}/{name}/dependabot/alerts",
            "attestations":f"/repos/{owner}/{name}/attestations",
        }.items():
            params={"includes_parents":"true"} if key=="rulesets" else None
            response = gh.get(path,params)
            d[key]=api_result(response)
            if key == "rulesets":
                d["rulesets_diagnostic"] = ruleset_diagnostic(response, path, params)

        # Environment secret evidence is metadata-only: the API returns secret names, not values.
        env_data=d.get("environments",{}).get("data",{}) if isinstance(d.get("environments",{}).get("data"),dict) else {}
        d["environment_secrets_by_name"]={}
        for env in env_data.get("environments",[]) if isinstance(env_data,dict) else []:
            env_name=env.get("name")
            if not env_name: continue
            rr=gh.get(f"/repos/{owner}/{name}/environments/{env_name}/secrets")
            d["environment_secrets_by_name"][env_name]=api_result(rr)
        d["environment_secrets"]={"status":200 if d["environment_secrets_by_name"] else 404,"data":None,"evidence":{"availability":"AVAILABLE" if d["environment_secrets_by_name"] else "NOT_COLLECTED","reason":"environment-specific evidence"}}

        default_branch = r.get("default_branch")
        if default_branch:
            d["default_branch_rules"] = api_result(
                gh.get(f"/repos/{owner}/{name}/rules/branches/{default_branch}")
            )
        else:
            d["default_branch_rules"] = {"status": 404, "data": None}

        wf=d["workflows"].get("data",{}).get("workflows",[]) if isinstance(d["workflows"].get("data"),dict) else []
        d["workflow_files"]={"items":wf}
        d["workflow_content"]=[]
        # Fetch each workflow definition; cap at 100/repository.
        for w in wf[:100]:
            p=w.get("path")
            if not p: continue
            rr=gh.get(f"/repos/{owner}/{name}/contents/{p}")
            txt=None; dat=body(rr)
            if isinstance(dat,dict) and dat.get("encoding")=="base64":
                import base64
                try: txt=base64.b64decode(dat["content"]).decode("utf-8","replace")
                except: pass
            d["workflow_content"].append({"path":p,"status":rr.status_code,"content":txt})
        d["files"]={}
        for p in ("CODEOWNERS",".github/CODEOWNERS","SECURITY.md",".github/SECURITY.md","CONTRIBUTING.md",".github/CONTRIBUTING.md"):
            rr=gh.get(f"/repos/{owner}/{name}/contents/{p}")
            dat=body(rr); txt=None
            if rr.status_code==200 and isinstance(dat,dict) and dat.get("encoding")=="base64":
                import base64
                try: txt=base64.b64decode(dat["content"]).decode("utf-8","replace")
                except: pass
            d["files"][p]={"status":rr.status_code,"data":dat,"content":txt}
        e["repository_evidence"][full]=d
        LOG.info("[REPO %s/%s] DONE %s workflows=%s elapsed=%.1fs", idx, len(repos), full, len(wf), time.monotonic()-repo_started)

    LOG.info("Team repository permissions phase: %s teams", len(e["teams"].get("items",[])))
    # Team repository permissions and direct repository collaborators.
    e["team_repository_evidence"]={}
    for idx,t in enumerate(e["teams"].get("items",[]),1):
        slug=t.get("slug")
        if not slug: continue
        e["team_repository_evidence"][slug]=api_result(gh.get(f"/orgs/{org}/teams/{slug}/repos"))
        LOG.info("[TEAM %s/%s] %s -> HTTP %s", idx, len(e["teams"].get("items",[])), slug, e["team_repository_evidence"][slug].get("status"))
    LOG.info("Direct collaborator phase: %s repositories", len(repos))
    e["repository_collaborator_evidence"]={}
    for idx,r in enumerate(repos,1):
        full=r["full_name"]; owner,name=full.split("/",1)
        e["repository_collaborator_evidence"][full]=api_result(gh.get(f"/repos/{owner}/{name}/collaborators",{"affiliation":"direct"}))
        if idx == 1 or idx % 10 == 0 or idx == len(repos):
            LOG.info("[COLLAB] %s/%s repositories processed", idx, len(repos))
    LOG.info("Assessment collection finished: repositories=%s teams=%s elapsed=%.1fs", len(repos), len(e["teams"].get("items",[])), time.monotonic()-started)
    return e

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


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--org")
    ap.add_argument("--catalog",default=DEFAULT_CATALOG,
                    help="Control catalog JSON (defaults to catalogs/latest/github_controls.json).")
    ap.add_argument("--out",default="github_assessment_output")
    ap.add_argument("--manual-evidence",default=None)
    ap.add_argument("--inactive-days",type=int,default=180)
    ap.add_argument("--self-check",action="store_true",
                    help="Validate the Python/TLS runtime and exit.")
    ap.add_argument("--log-level",choices=("DEBUG","INFO","WARNING","ERROR"),default="INFO",
                    help="Console log level (default: INFO).")
    ap.add_argument("--github-app-id",default=os.getenv("GITHUB_APP_ID"),help="GitHub App ID (or GITHUB_APP_ID).")
    ap.add_argument("--github-app-private-key-file",default=os.getenv("GITHUB_APP_PRIVATE_KEY_FILE"),help="Path to GitHub App private key PEM (or GITHUB_APP_PRIVATE_KEY_FILE).")
    ap.add_argument("--github-app-private-key",default=os.getenv("GITHUB_APP_PRIVATE_KEY"),help="GitHub App private key PEM/base64 (or GITHUB_APP_PRIVATE_KEY).")
    ap.add_argument("--github-installation-id",default=os.getenv("GITHUB_APP_INSTALLATION_ID"),help="Optional installation ID; otherwise resolve from the organization.")
    ap.add_argument("--github-token",default=os.getenv("GITHUB_TOKEN"),help="Legacy PAT/fine-grained token fallback (or GITHUB_TOKEN).")
    args=ap.parse_args()
    logging.basicConfig(level=getattr(logging,args.log_level),format="%(asctime)s | %(levelname)s | %(message)s",datefmt="%H:%M:%S")

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
        f"# GitHub Enterprise Assessment Framework — {args.org}",
        "",
        "> Production assessment report generated from the read-only GitHub assessment engine.",
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
        ("Scored controls",f"{scored_count}/{total_controls}"),
        ("Failures",result["summary"]["failures"]),
        ("Critical failures",critical_fail),
        ("Not assessed",result["summary"]["not_assessed"]),
        ("Permission audit",auth_permission_audit.get("status","UNKNOWN")),
    ])

    md += ["","## Technical Information","",]
    md += md_table([
        ("Item","Value"),
        ("Execution date",evidence["metadata"].get("collected_at","N/A")),
        ("Authentication method",(auth_metadata or {}).get("type","token")),
        ("Engine version",ENGINE_VERSION),
        ("Framework version",catalog.get("version","N/A")),
        ("GitHub API version",evidence["metadata"].get("api_version","N/A")),
        ("Assessment principal",(auth_metadata or {}).get("type","token")),
        ("Permission posture","Read-only" if auth_permission_audit.get("read_only_assessment") else "Review required"),
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
        "Numeric control scores remain available as a separate diagnostic metric, but they no longer determine maturity. Domains with insufficient evidence coverage are marked **provisional**.",
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
           "Domain maturity is expressed using the GitHub Well-Architected **Start / Mature / Advance** terminology. Maturity is determined by achievement of the control stages in the catalog, not by the numeric score. The **Score** remains a diagnostic metric and **Coverage** shows how much of the domain had a scored result.","",
    ]
    md += md_table([("Domain","Stage","Score","Scored","Coverage","Basis")]+maturity_rows)
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

    LOG.info("Assessment complete. Outputs written to %s", os.path.abspath(args.out))
    print(json.dumps(result["summary"],indent=2))
    print(f"Outputs written to {args.out}/")

if __name__=="__main__":
    main()
