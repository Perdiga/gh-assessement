---
id: installation
title: Installation
description: Set up the Python assessment engine and GitHub authentication.
sidebar_position: 2
---

# Installation

## Prerequisites

- Python 3.10 or newer.
- A GitHub App installed on the target organization (recommended), or a compatible fine-grained token for the legacy fallback.
- Read permissions for the evidence sources required by the controls you intend to assess.

## Install the engine

From the repository root, create and activate a virtual environment, then install the engine dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r engine/requirements.txt
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

## Configure authentication

The engine loads the repository-root `.env` file. Set either GitHub App credentials or the legacy `GITHUB_TOKEN` fallback. Do not commit `.env` or private keys.

Recommended GitHub App settings:

```dotenv
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_FILE=/absolute/path/to/assessment-app.private-key.pem
GITHUB_APP_INSTALLATION_ID=
```

`GITHUB_APP_INSTALLATION_ID` is optional when the app is installed on the organization and can be resolved automatically. The key-file path is opened relative to the process working directory; an absolute path avoids ambiguity.

Alternatively, `GITHUB_APP_PRIVATE_KEY` accepts a PEM or base64-encoded private key. Avoid setting both private-key forms. For development or troubleshooting, `GITHUB_TOKEN` enables the legacy PAT/fine-grained token path; GitHub App installation authentication is preferred.

The GitHub App must be installed on the target organization and have access to the repositories and read permissions needed for collection. Endpoints requiring elevated write permissions are intentionally not collected under the read-only posture; affected controls remain unassessed or report an evidence blocker.

## Verify the runtime

From the engine directory:

```bash
cd engine
python main.py --self-check
```

The self-check validates that Python is using a compatible OpenSSL runtime.
