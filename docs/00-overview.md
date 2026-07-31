# nazar-audit

A modern, security-conscious package vulnerability scanner for the JavaScript ecosystem.

Named after the **nazar** -- the protective eye amulet found across the Mediterranean -- nazar-audit watches over your dependencies and wards off malicious or vulnerable packages.

## What it does

nazar-audit wraps the native package manager audit (npm, pnpm, Yarn, Bun) and adds:

- **Exception management** with expiry dates, notes, and audit trail
- **Multiple output formats** (table, JSON, SARIF, Markdown)
- **Fix availability display** showing upgrade paths
- **Severity thresholds** that independently control exit behavior and table display
- **Module-level and path-level ignoring** with wildcard support
- **Interactive triage workflow** for teams managing audit in CI
- **Lockfile integrity validation** for supply chain protection

## Why build this

The existing tools each solve part of the problem but none solve all of it:

| Tool | Limitation |
|---|---|
| `npm audit` | No exception management, no output filtering, raw JSON schema |
| better-npm-audit | Unmaintained, critical RCE vulnerability, npm-only, no JSON output |
| audit-ci | CI-only, no interactive mode, no fix availability display |
| npm-audit-resolver | npm-only, no structured output, aging codebase |
| Snyk | Commercial, heavy, requires account |

nazar-audit fills the gap: a lightweight, fast, zero-dependency CLI with excellent exception management, multiple output formats (including SARIF for GitHub Code Scanning), multi-package-manager support, and fix availability reporting -- designed for both local development and CI/CD pipelines.

## Architecture

```
CLI (commander / citty)
  |
  +-- Package Manager Adapter (npm / pnpm / yarn / bun)
  |     |
  |     +-- execFile('<pm>', ['audit', '--json'])  <-- secure, no shell
  |     +-- normalize JSON -> internal Vulnerability model
  |
  +-- Exception Engine
  |     |
  |     +-- config file parser (.nazar.yml / .nazar.jsonc)
  |     +-- match by ID / CVE / GHSA / CWE / module / path
  |     +-- expiry validation
  |     +-- unused exception detection
  |
  +-- Reporter
  |     |
  |     +-- Table (colored, configurable columns)
  |     +-- JSON (normalized)
  |     +-- SARIF 2.1.0
  |     +-- Markdown
  |
  +-- Exit Code Logic
        |
        +-- severity threshold
        +-- fail-on mode (all / upgradable / patchable)
```

## Documentation

- [Phase 0: MVP](./01-phase-0-mvp.md) -- Core scanning, exceptions, table + JSON output
- [Phase 1: High Value](./02-phase-1-high-value.md) -- SARIF, multi-PM, advanced exceptions, CI features
- [Phase 2: Differentiators](./03-phase-2-differentiators.md) -- Guided remediation, reachability, compliance
- [Phase 3: Aspirational](./04-phase-3-aspirational.md) -- Supply chain signals, signature verification
- [Data Model](./05-data-model.md) -- Vulnerability schema, npm audit JSON mapping
- [Competitive Landscape](./06-competitive-landscape.md) -- How nazar-audit compares to existing tools
