import base64
import logging
import time
from datetime import datetime, timezone

from github_client import API_VERSION, GH, api_result, body, ruleset_diagnostic

LOG = logging.getLogger("github_assessment")


def collect(token, org, auth_metadata=None):
    started = time.monotonic()
    github = GH(token, auth_metadata)
    collected_at = datetime.now(timezone.utc).isoformat()
    LOG.info("Assessment collection started: organization=%s API=%s", org, API_VERSION)
    evidence = {
        "metadata": {
            "org": org,
            "collected_at": collected_at,
            "api_version": API_VERSION,
            "authentication": auth_metadata or {"type": "token"},
        },
        "organization": {},
        "members": {},
        "owners": {},
        "outside_collaborators": {},
        "teams": {},
        "repositories": {},
        "org_rulesets": {},
        "audit_log": {},
    }

    def one(key, path, params=None):
        LOG.info("[ORG] %s -> GET %s", key, path)
        evidence[key] = api_result(github.get(path, params))
        LOG.info(
            "[ORG] %s -> HTTP %s (%.1fs)",
            key,
            evidence[key].get("status"),
            time.monotonic() - started,
        )

    def many(key, path, params=None):
        LOG.info("[ORG] %s -> GET %s (paginated)", key, path)
        evidence[key] = github.page(path, params)
        LOG.info(
            "[ORG] %s -> HTTP %s, items=%s (%.1fs)",
            key,
            evidence[key].get("status"),
            len(evidence[key].get("items", [])),
            time.monotonic() - started,
        )

    one("organization", f"/orgs/{org}")
    many("members", f"/orgs/{org}/members")
    many("owners", f"/orgs/{org}/members", {"role": "admin"})
    many("outside_collaborators", f"/orgs/{org}/outside-collaborators")
    many("teams", f"/orgs/{org}/teams")
    many("repositories", f"/orgs/{org}/repos", {"type": "all", "sort": "full_name"})
    LOG.info("[ORG] org_rulesets -> GET /orgs/%s/rulesets (paginated)", org)
    evidence["org_rulesets"] = github.page(f"/orgs/{org}/rulesets")
    evidence["org_rulesets_diagnostic"] = {
        "path": f"/orgs/{org}/rulesets",
        "http_status": evidence["org_rulesets"].get("status"),
        "accepted_github_permissions": evidence["org_rulesets"].get(
            "accepted_github_permissions", []
        ),
        "item_count": len(evidence["org_rulesets"].get("items", [])),
        "source_type_counts": {},
        "evidence": evidence["org_rulesets"].get("evidence", {}),
    }

    one("actions_permissions", f"/orgs/{org}/actions/permissions")
    one("actions_selected", f"/orgs/{org}/actions/permissions/selected-actions")
    one("actions_workflow_permissions", f"/orgs/{org}/actions/permissions/workflow")
    one("self_hosted_runner_policy", f"/orgs/{org}/actions/permissions/self-hosted-runners")
    many("runner_groups", f"/orgs/{org}/actions/runner-groups")
    one("audit_log", f"/orgs/{org}/audit-log", {"per_page": 100})
    many("attestation_repositories", f"/orgs/{org}/attestations/repositories")
    many("org_code_scanning_alerts", f"/orgs/{org}/code-scanning/alerts")
    many("org_secret_scanning_alerts", f"/orgs/{org}/secret-scanning/alerts")
    one("scim_users", f"/scim/v2/organizations/{org}/Users", {"startIndex": 1, "count": 100})

    repositories = evidence["repositories"].get("items", [])
    LOG.info("Repository evidence phase: %s repositories discovered", len(repositories))
    evidence["repository_evidence"] = {}
    for index, repository in enumerate(repositories, 1):
        full_name = repository["full_name"]
        owner, name = full_name.split("/", 1)
        repository_started = time.monotonic()
        LOG.info("[REPO %s/%s] START %s", index, len(repositories), full_name)
        repo_evidence = {"repo": api_result(github.get(f"/repos/{owner}/{name}"))}

        paths = {
            "rulesets": f"/repos/{owner}/{name}/rulesets",
            "environments": f"/repos/{owner}/{name}/environments",
            "collaborators": f"/repos/{owner}/{name}/collaborators",
            "workflows": f"/repos/{owner}/{name}/actions/workflows",
            "code_scanning": f"/repos/{owner}/{name}/code-scanning/analyses",
            "secret_scanning": f"/repos/{owner}/{name}/secret-scanning/alerts",
            "dependabot": f"/repos/{owner}/{name}/dependabot/alerts",
            "attestations": f"/repos/{owner}/{name}/attestations",
        }
        for key, path in paths.items():
            params = {"includes_parents": "true"} if key == "rulesets" else None
            response = github.get(path, params)
            repo_evidence[key] = api_result(response)
            if key == "rulesets":
                repo_evidence["rulesets_diagnostic"] = ruleset_diagnostic(
                    response, path, params
                )

        environment_data = repo_evidence.get("environments", {}).get("data", {})
        if not isinstance(environment_data, dict):
            environment_data = {}
        repo_evidence["environment_secrets_by_name"] = {}
        for environment in environment_data.get("environments", []):
            environment_name = environment.get("name")
            if not environment_name:
                continue
            response = github.get(
                f"/repos/{owner}/{name}/environments/{environment_name}/secrets"
            )
            repo_evidence["environment_secrets_by_name"][environment_name] = api_result(
                response
            )
        has_environment_secrets = bool(repo_evidence["environment_secrets_by_name"])
        repo_evidence["environment_secrets"] = {
            "status": 200 if has_environment_secrets else 404,
            "data": None,
            "evidence": {
                "availability": "AVAILABLE" if has_environment_secrets else "NOT_COLLECTED",
                "reason": "environment-specific evidence",
            },
        }

        default_branch = repository.get("default_branch")
        if default_branch:
            repo_evidence["default_branch_rules"] = api_result(
                github.get(f"/repos/{owner}/{name}/rules/branches/{default_branch}")
            )
        else:
            repo_evidence["default_branch_rules"] = {"status": 404, "data": None}

        workflow_data = repo_evidence["workflows"].get("data", {})
        workflows = workflow_data.get("workflows", []) if isinstance(workflow_data, dict) else []
        repo_evidence["workflow_files"] = {"items": workflows}
        repo_evidence["workflow_content"] = []
        for workflow in workflows[:100]:
            path = workflow.get("path")
            if not path:
                continue
            response = github.get(f"/repos/{owner}/{name}/contents/{path}")
            content_data = body(response)
            content = None
            if isinstance(content_data, dict) and content_data.get("encoding") == "base64":
                try:
                    content = base64.b64decode(content_data["content"]).decode(
                        "utf-8", "replace"
                    )
                except Exception:
                    pass
            repo_evidence["workflow_content"].append(
                {"path": path, "status": response.status_code, "content": content}
            )

        repo_evidence["files"] = {}
        paths = (
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "SECURITY.md",
            ".github/SECURITY.md",
            "CONTRIBUTING.md",
            ".github/CONTRIBUTING.md",
        )
        for path in paths:
            response = github.get(f"/repos/{owner}/{name}/contents/{path}")
            content_data = body(response)
            content = None
            if (
                response.status_code == 200
                and isinstance(content_data, dict)
                and content_data.get("encoding") == "base64"
            ):
                try:
                    content = base64.b64decode(content_data["content"]).decode(
                        "utf-8", "replace"
                    )
                except Exception:
                    pass
            repo_evidence["files"][path] = {
                "status": response.status_code,
                "data": content_data,
                "content": content,
            }

        evidence["repository_evidence"][full_name] = repo_evidence
        LOG.info(
            "[REPO %s/%s] DONE %s workflows=%s elapsed=%.1fs",
            index,
            len(repositories),
            full_name,
            len(workflows),
            time.monotonic() - repository_started,
        )

    teams = evidence["teams"].get("items", [])
    LOG.info("Team repository permissions phase: %s teams", len(teams))
    evidence["team_repository_evidence"] = {}
    for index, team in enumerate(teams, 1):
        slug = team.get("slug")
        if not slug:
            continue
        team_evidence = api_result(github.get(f"/orgs/{org}/teams/{slug}/repos"))
        evidence["team_repository_evidence"][slug] = team_evidence
        LOG.info(
            "[TEAM %s/%s] %s -> HTTP %s",
            index,
            len(teams),
            slug,
            team_evidence.get("status"),
        )

    LOG.info("Direct collaborator phase: %s repositories", len(repositories))
    evidence["repository_collaborator_evidence"] = {}
    for index, repository in enumerate(repositories, 1):
        full_name = repository["full_name"]
        owner, name = full_name.split("/", 1)
        collaborator_evidence = api_result(
            github.get(
                f"/repos/{owner}/{name}/collaborators",
                {"affiliation": "direct"},
            )
        )
        evidence["repository_collaborator_evidence"][full_name] = collaborator_evidence
        if index == 1 or index % 10 == 0 or index == len(repositories):
            LOG.info("[COLLAB] %s/%s repositories processed", index, len(repositories))

    LOG.info(
        "Assessment collection finished: repositories=%s teams=%s elapsed=%.1fs",
        len(repositories),
        len(teams),
        time.monotonic() - started,
    )
    return evidence
