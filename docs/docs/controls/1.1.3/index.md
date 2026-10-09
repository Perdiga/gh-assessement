---
id: 1.1.3
title: "Control catalog 1.1.3"
sidebar_position: 1
---

# Control catalog 1.1.3

This reference contains 132 controls generated from `catalogs/1.1.3/github_controls.json`.

Control content is generated from the versioned JSON catalog. After adding or updating a catalog, regenerate pages by running `npm run docs:generate` from the `docs/` directory.

## CI/CD & GitHub Actions

- [CI-055: Required CI checks are enforced](./ci-cd-github-actions/CI-055)
- [CI-056: Reusable workflows are used where standardization is valuable](./ci-cd-github-actions/CI-056)
- [CI-057: Workflow permissions follow least privilege](./ci-cd-github-actions/CI-057)
- [CI-058: Actions can only run from approved sources](./ci-cd-github-actions/CI-058)
- [CI-059: Third-party Actions are governed](./ci-cd-github-actions/CI-059)
- [CI-060: Actions are pinned appropriately](./ci-cd-github-actions/CI-060)
- [CI-061: Production deployments require protected environments](./ci-cd-github-actions/CI-061)
- [CI-062: Environment secrets are restricted](./ci-cd-github-actions/CI-062)
- [CI-063: Deployment branches are restricted](./ci-cd-github-actions/CI-063)
- [CI-064: Self-hosted runners are governed](./ci-cd-github-actions/CI-064)
- [CI-065: Runner groups are used for isolation](./ci-cd-github-actions/CI-065)
- [CI-066: Workflow concurrency is controlled](./ci-cd-github-actions/CI-066)
- [CI-067: CI artifacts have retention governance](./ci-cd-github-actions/CI-067)
- [CI-068: Failed deployments have rollback procedures](./ci-cd-github-actions/CI-068)

## Code Review & Collaboration

- [REV-047: Pull requests are required for protected branches](./code-review-collaboration/REV-047)
- [REV-048: Minimum approving reviews are defined](./code-review-collaboration/REV-048)
- [REV-049: Code owner review is required for critical paths](./code-review-collaboration/REV-049)
- [REV-050: Stale approvals are dismissed when required](./code-review-collaboration/REV-050)
- [REV-051: Review dismissal is restricted](./code-review-collaboration/REV-051)
- [REV-052: Conversation resolution is required where appropriate](./code-review-collaboration/REV-052)
- [REV-053: Security findings have a defined review path](./code-review-collaboration/REV-053)
- [REV-054: Documentation standards are defined](./code-review-collaboration/REV-054)

## Cost & AI Governance

- [COST-126: GitHub resource usage is attributable](./cost-ai-governance/COST-126)
- [COST-127: AI usage is attributable where applicable](./cost-ai-governance/COST-127)
- [COST-128: AI budgets are defined where applicable](./cost-ai-governance/COST-128)
- [COST-129: AI credit consumption anomalies are monitored](./cost-ai-governance/COST-129)
- [COST-130: Actions compute usage is reviewed](./cost-ai-governance/COST-130)
- [COST-131: Self-hosted runner capacity is governed](./cost-ai-governance/COST-131)
- [COST-132: Repository/archive costs are reviewed](./cost-ai-governance/COST-132)

## Developer Productivity

- [PROD-110: Repository templates are available](./developer-productivity/PROD-110)
- [PROD-111: Standard workflows are available](./developer-productivity/PROD-111)
- [PROD-112: New repositories receive baseline controls](./developer-productivity/PROD-112)
- [PROD-113: Developer onboarding is documented](./developer-productivity/PROD-113)
- [PROD-114: Engineering standards are discoverable](./developer-productivity/PROD-114)
- [PROD-115: Common automation is reusable](./developer-productivity/PROD-115)
- [PROD-116: Developer feedback channels exist](./developer-productivity/PROD-116)
- [PROD-117: Engineering productivity metrics are reviewed](./developer-productivity/PROD-117)

## Governance Risk & Compliance

- [GRC-118: Exceptions have owner, rationale and expiry](./governance-risk-compliance/GRC-118)
- [GRC-119: Risk acceptance is documented](./governance-risk-compliance/GRC-119)
- [GRC-120: Controls are periodically reassessed](./governance-risk-compliance/GRC-120)
- [GRC-121: Policy ownership is explicit](./governance-risk-compliance/GRC-121)
- [GRC-122: Regulatory requirements are mapped to controls](./governance-risk-compliance/GRC-122)
- [GRC-123: Evidence is reproducible and timestamped](./governance-risk-compliance/GRC-123)
- [GRC-124: NOT ASSESSED findings are tracked](./governance-risk-compliance/GRC-124)
- [GRC-125: Critical findings have remediation owners](./governance-risk-compliance/GRC-125)

## Identity & Access

- [IAM-011: SSO enforcement is enabled where required](./identity-access/IAM-011)
- [IAM-012: MFA requirement is enabled where applicable](./identity-access/IAM-012)
- [IAM-013: SCIM provisioning is implemented where applicable](./identity-access/IAM-013)
- [IAM-014: Deprovisioned identities are removed promptly](./identity-access/IAM-014)
- [IAM-015: Access reviews are periodic](./identity-access/IAM-015)
- [IAM-016: Suspended members are reviewed](./identity-access/IAM-016)
- [IAM-017: Inactive accounts are identified](./identity-access/IAM-017)
- [IAM-018: Enterprise-to-org access is documented](./identity-access/IAM-018)

## Observability & Audit

- [OPS-090: Organization audit logs are available](./observability-audit/OPS-090)
- [OPS-091: Audit logs are retained according to policy](./observability-audit/OPS-091)
- [OPS-092: Audit logs are forwarded to monitoring/SIEM where required](./observability-audit/OPS-092)
- [OPS-093: Administrative events are monitored](./observability-audit/OPS-093)
- [OPS-094: Authentication events are monitored](./observability-audit/OPS-094)
- [OPS-095: Repository permission changes are monitored](./observability-audit/OPS-095)
- [OPS-096: Actions security events are monitored](./observability-audit/OPS-096)
- [OPS-097: Security alerts are monitored](./observability-audit/OPS-097)
- [OPS-098: CI/CD reliability metrics are tracked](./observability-audit/OPS-098)
- [OPS-099: SLO/SLA exists for critical delivery pipelines](./observability-audit/OPS-099)

## Organization Governance

- [ORG-001: Default repository permission is restrictive](./organization-governance/ORG-001)
- [ORG-002: Repository creation visibility is controlled](./organization-governance/ORG-002)
- [ORG-003: Public repository creation is explicitly governed](./organization-governance/ORG-003)
- [ORG-004: Member repository creation is controlled](./organization-governance/ORG-004)
- [ORG-005: Organization owners are limited and reviewed](./organization-governance/ORG-005)
- [ORG-006: Outside collaborators are inventoried](./organization-governance/ORG-006)
- [ORG-007: Outside collaborators have business justification](./organization-governance/ORG-007)
- [ORG-008: Repository lifecycle is governed](./organization-governance/ORG-008)
- [ORG-009: Inactive repositories are identified](./organization-governance/ORG-009)
- [ORG-010: Archived repositories are reviewed](./organization-governance/ORG-010)

## Repository Governance

- [REPO-027: Repositories have documented ownership](./repository-governance/REPO-027)
- [REPO-028: Repository visibility is appropriate](./repository-governance/REPO-028)
- [REPO-029: Public repositories have explicit approval](./repository-governance/REPO-029)
- [REPO-030: Internal repositories are used where appropriate](./repository-governance/REPO-030)
- [REPO-031: Repository descriptions identify purpose](./repository-governance/REPO-031)
- [REPO-032: Topics/classification metadata is present](./repository-governance/REPO-032)
- [REPO-033: Archived repositories are read-only](./repository-governance/REPO-033)
- [REPO-034: Template repositories are governed](./repository-governance/REPO-034)
- [REPO-035: Repository naming conventions are followed](./repository-governance/REPO-035)
- [REPO-036: Fork policy is appropriate](./repository-governance/REPO-036)

## Resilience & Disaster Recovery

- [DR-100: Critical repositories have an independent recovery strategy](./resilience-disaster-recovery/DR-100)
- [DR-101: Recovery source is independent of primary failure domain](./resilience-disaster-recovery/DR-101)
- [DR-102: Break-glass responders are identified](./resilience-disaster-recovery/DR-102)
- [DR-103: Recovery credentials are independently available](./resilience-disaster-recovery/DR-103)
- [DR-104: Recovery procedures are documented](./resilience-disaster-recovery/DR-104)
- [DR-105: Recovery procedures are tested periodically](./resilience-disaster-recovery/DR-105)
- [DR-106: RPO is defined for critical repositories](./resilience-disaster-recovery/DR-106)
- [DR-107: RTO is defined for critical repositories](./resilience-disaster-recovery/DR-107)
- [DR-108: Mirror freshness is monitored](./resilience-disaster-recovery/DR-108)
- [DR-109: Recovery changes are reconciled after incidents](./resilience-disaster-recovery/DR-109)

## Security & Software Supply Chain

- [SEC-069: Dependency graph is enabled where applicable](./security-software-supply-chain/SEC-069)
- [SEC-070: Dependabot alerts are enabled](./security-software-supply-chain/SEC-070)
- [SEC-071: Dependabot security updates are enabled](./security-software-supply-chain/SEC-071)
- [SEC-072: Secret scanning is enabled](./security-software-supply-chain/SEC-072)
- [SEC-073: Push protection is enabled](./security-software-supply-chain/SEC-073)
- [SEC-074: Code scanning is enabled for supported repositories](./security-software-supply-chain/SEC-074)
- [SEC-075: Security policy exists for relevant repositories](./security-software-supply-chain/SEC-075)
- [SEC-076: Vulnerability alerts have remediation SLAs](./security-software-supply-chain/SEC-076)
- [SEC-077: Critical dependencies are monitored](./security-software-supply-chain/SEC-077)
- [SEC-078: SBOM strategy exists where required](./security-software-supply-chain/SEC-078)
- [SEC-079: Third-party Actions are pinned and reviewed](./security-software-supply-chain/SEC-079)
- [SEC-080: Release artifacts are provenance-controlled](./security-software-supply-chain/SEC-080)
- [SEC-081: Security findings are centrally visible](./security-software-supply-chain/SEC-081)

## Shared Platform & Reusability

- [SUP-082: Shared workflows have clear ownership](./shared-platform-reusability/SUP-082)
- [SUP-083: Shared workflows have versioning strategy](./shared-platform-reusability/SUP-083)
- [SUP-084: Shared Actions have contribution guidelines](./shared-platform-reusability/SUP-084)
- [SUP-085: Reusable components are discoverable](./shared-platform-reusability/SUP-085)
- [SUP-086: Shared workflows are security-reviewed](./shared-platform-reusability/SUP-086)
- [SUP-087: Shared workflows have lifecycle/deprecation policy](./shared-platform-reusability/SUP-087)
- [SUP-088: Common CI patterns are standardized](./shared-platform-reusability/SUP-088)
- [SUP-089: Shared components have adoption metrics](./shared-platform-reusability/SUP-089)

## Source Control

- [SCM-037: Default branches are protected](./source-control/SCM-037)
- [SCM-038: Direct pushes to protected branches are restricted](./source-control/SCM-038)
- [SCM-039: Force pushes are restricted](./source-control/SCM-039)
- [SCM-040: Branch deletion is restricted](./source-control/SCM-040)
- [SCM-041: Signed commits are required where appropriate](./source-control/SCM-041)
- [SCM-042: Rulesets are centrally governed](./source-control/SCM-042)
- [SCM-043: Rulesets target critical repositories](./source-control/SCM-043)
- [SCM-044: Legacy branch protection gaps are identified](./source-control/SCM-044)
- [SCM-045: Tag protection/release controls exist where needed](./source-control/SCM-045)
- [SCM-046: Repository admins cannot bypass critical controls without governance](./source-control/SCM-046)

## Teams & Authorization

- [TEAM-019: Repository access is primarily team-based](./teams-authorization/TEAM-019)
- [TEAM-020: Direct admin grants are minimized](./teams-authorization/TEAM-020)
- [TEAM-021: Team maintainers are limited](./teams-authorization/TEAM-021)
- [TEAM-022: Nested team structure is intentional](./teams-authorization/TEAM-022)
- [TEAM-023: Teams have documented ownership](./teams-authorization/TEAM-023)
- [TEAM-024: Empty teams are reviewed](./teams-authorization/TEAM-024)
- [TEAM-025: Teams without repositories are reviewed](./teams-authorization/TEAM-025)
- [TEAM-026: Sensitive repositories use dedicated access groups](./teams-authorization/TEAM-026)
