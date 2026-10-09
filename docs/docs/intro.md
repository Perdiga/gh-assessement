---
id: intro
slug: /
title: GitHub Enterprise Assessment Framework
description: Overview of the evidence-driven GitHub Enterprise assessment methodology and documentation.
sidebar_position: 1
---

# GitHub Enterprise Assessment Framework

A read-only, evidence-driven assessment of a GitHub organization against a versioned catalog of governance, identity, repository, source-control, CI/CD, security, operations, resilience, productivity, and cost controls.

The assessment collects evidence from GitHub APIs and supplied manual evidence, evaluates each control, and produces findings, permission manifests, evidence provenance, and an audit-oriented Markdown report. Missing evidence is reported as **NOT ASSESSED**, never as a pass.

## What this project is

The control requirements, evaluation logic, scoring, severity, exceptions, and maturity-stage assignments belong to this assessment methodology. GitHub Well-Architected is the external reference for architecture principles and the **Start**, **Mature**, and **Advance** progression; it does not define this catalog's exact controls or scoring rules.

The assessment is read-only. It gathers organization and repository configuration and does not modify GitHub resources.

## Documentation map

- [Install the engine](./installation) for prerequisites, Python dependencies, and authentication configuration.
- [Run an assessment](./usage) for command examples, evidence inputs, and output files.
- [Browse the versioned control catalog](./controls) for each control's objective, evidence, evaluation logic, expected result, exception criteria, remediation, and maturity basis.

## Current catalog

The current catalog version is **1.1.2**, containing 132 controls. Pages are generated from `catalogs/1.1.2/github_controls.json`; `catalogs/latest/github_controls.json` is the current alias. Historical catalog versions remain under their own versioned paths.
