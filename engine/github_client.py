import base64
import logging
import os
import re
import ssl
import time

API = "https://api.github.com"
API_VERSION = "2026-03-10"
AUTHENTICATION_VERSION = "1.1"
USER_AGENT = "github-enterprise-assessment-framework/1.8.1"
LOG = logging.getLogger("github_assessment")


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
        self.auth_metadata = auth_metadata or {"type": "token"}
        self.s.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            }
        )

    def get(self, path, params=None):
        url = path if path.startswith("http") else API + path
        last_error = None
        for attempt in range(1, 7):
            try:
                response = self.s.get(url, params=params, timeout=45)
            except Exception as exc:
                last_error = exc
                if attempt >= 6:
                    LOG.error("GET %s failed after %s attempts: %s", path, attempt, exc)
                    raise
                delay = min(30, 2 ** (attempt - 1))
                LOG.warning(
                    "GET %s connection error (%s); retrying in %ss [attempt %s/6]",
                    path,
                    exc,
                    delay,
                    attempt,
                )
                time.sleep(delay)
                continue

            if response.status_code == 429 or (
                response.status_code == 403
                and response.headers.get("X-RateLimit-Remaining") == "0"
            ):
                retry = int(response.headers.get("Retry-After", "0") or 0)
                if not retry:
                    reset = int(response.headers.get("X-RateLimit-Reset", "0") or 0)
                    retry = max(1, min(60, reset - int(time.time())))
                LOG.warning("Rate limited: retrying in %ss", retry)
                time.sleep(retry)
                continue

            if response.status_code in (502, 503, 504, 520, 522, 524) and attempt < 6:
                delay = min(30, 2 ** (attempt - 1))
                LOG.warning(
                    "GET %s -> HTTP %s; retrying in %ss [attempt %s/6]",
                    path,
                    response.status_code,
                    delay,
                    attempt,
                )
                time.sleep(delay)
                continue

            if response.status_code >= 400 and response.status_code != 404:
                LOG.warning(
                    "GET %s -> HTTP %s",
                    path if path.startswith("/") else url,
                    response.status_code,
                )
            elif response.status_code == 404:
                LOG.debug(
                    "GET %s -> HTTP 404 (resource/file not found or inaccessible)",
                    path,
                )
            return response

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
                availability, reason = classify_http(
                    response.status_code,
                    body(response),
                    response.text[:500],
                )
                return {
                    "status": response.status_code,
                    "items": items,
                    "error": response.text[:500],
                    "evidence": {"availability": availability, "reason": reason},
                    "accepted_github_permissions": observed_permissions(response),
                }

            data = response.json()
            if not isinstance(data, list):
                return {
                    "status": 200,
                    "data": data,
                    "items": items,
                    "accepted_github_permissions": observed_permissions(response),
                }

            items.extend(data)
            url = self._next_link(response)

        return {
            "status": 200,
            "items": items,
            "accepted_github_permissions": observed_permissions(response),
        }


class GitHubAppAuthenticator:
    """Create short-lived installation credentials for a GitHub App."""

    def __init__(self, app_id, private_key, installation_id=None):
        check_runtime()
        import requests

        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError(
                "PyJWT is required for GitHub App authentication; install project dependencies."
            ) from exc

        self.app_id = str(app_id)
        self.private_key = private_key
        self.installation_id = int(installation_id) if installation_id else None
        self.jwt = jwt
        self.s = requests.Session()
        self.s.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            }
        )

    def app_jwt(self):
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self.app_id}
        return self.jwt.encode(payload, self.private_key, algorithm="RS256")

    def _request(self, method, path, **kwargs):
        url = path if path.startswith("http") else API + path
        response = self.s.request(method, url, timeout=45, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(
                f"GitHub App authentication request failed: HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )
        return response

    def resolve_installation(self, org):
        if self.installation_id:
            return self.installation_id
        response = self._request(
            "GET",
            f"/orgs/{org}/installation",
            headers={"Authorization": f"Bearer {self.app_jwt()}"},
        )
        self.installation_id = int(response.json()["id"])
        return self.installation_id

    def authenticate(self, org):
        installation_id = self.resolve_installation(org)
        response = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {self.app_jwt()}"},
        )
        data = response.json()
        repositories = data.get("repositories")
        metadata = {
            "type": "github_app_installation",
            "app_id": int(self.app_id) if self.app_id.isdigit() else self.app_id,
            "installation_id": installation_id,
            "organization": org,
            "permissions": data.get("permissions", {}),
            "repository_count": len(repositories) if isinstance(repositories, list) else None,
            "repository_selection": "scoped" if isinstance(repositories, list) else "installation_default",
            "expires_at": data.get("expires_at"),
            "authentication_version": AUTHENTICATION_VERSION,
        }
        return data["token"], metadata


def load_private_key(value=None, path=None):
    if path:
        with open(path, encoding="utf-8") as key_file:
            return key_file.read()
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


def body(response):
    try:
        return response.json()
    except Exception:
        return None


def observed_permissions(response):
    raw = response.headers.get("X-Accepted-GitHub-Permissions", "")
    if not raw:
        return []
    return [permission.strip() for permission in raw.split(",") if permission.strip()]


def classify_http(status, data=None, text=""):
    message = str(data.get("message", "")) if isinstance(data, dict) else ""
    message = f"{message} {text or ''}".lower()
    if status == 200:
        return "AVAILABLE", "ok"
    if status in (401, 403) and any(
        value in message
        for value in ("resource not accessible", "forbidden", "bad credentials", "authentication")
    ):
        return "UNAVAILABLE", "permission_denied"
    if status in (403, 404) and any(
        value in message
        for value in (
            "advanced security must be enabled",
            "must be enabled",
            "secret scanning is disabled",
            "disabled on this repository",
        )
    ):
        return "AVAILABLE", "feature_disabled"
    if status == 429:
        return "UNAVAILABLE", "rate_limited"
    if status >= 500:
        return "UNAVAILABLE", "server_error"
    if status in (401, 403):
        return "UNAVAILABLE", "access_denied"
    if status == 404:
        return "UNAVAILABLE", "not_found_or_inaccessible"
    if status >= 400:
        return "UNAVAILABLE", "http_error"
    return "UNAVAILABLE", "unknown"


def api_result(response):
    data = (
        body(response)
        if response.headers.get("content-type", "").startswith("application/json")
        else response.text[:1000]
    )
    availability, reason = classify_http(
        response.status_code,
        data,
        response.text[:1000],
    )
    return {
        "status": response.status_code,
        "data": data,
        "evidence": {"availability": availability, "reason": reason},
        "accepted_github_permissions": observed_permissions(response),
    }


def ruleset_diagnostic(response, path, params=None):
    """Capture safe diagnostic metadata for ruleset access without response bodies or secrets."""
    data = body(response)
    items = data if isinstance(data, list) else (data.get("rulesets", []) if isinstance(data, dict) else [])
    return {
        "path": path,
        "params": params or {},
        "http_status": response.status_code,
        "accepted_github_permissions": observed_permissions(response),
        "oauth_scopes": response.headers.get("X-OAuth-Scopes", ""),
        "accepted_github_permissions_header": response.headers.get(
            "X-Accepted-GitHub-Permissions", ""
        ),
        "item_count": len(items) if isinstance(items, list) else None,
        "source_type_counts": (
            {
                source_type: sum(
                    1
                    for item in items
                    if isinstance(item, dict) and item.get("source_type") == source_type
                )
                for source_type in sorted(
                    {
                        item.get("source_type")
                        for item in items
                        if isinstance(item, dict) and item.get("source_type")
                    }
                )
            }
            if isinstance(items, list)
            else {}
        ),
        "evidence": classify_http(response.status_code, data, response.text[:1000]),
    }
