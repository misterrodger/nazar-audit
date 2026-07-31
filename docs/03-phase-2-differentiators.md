# Phase 2: Differentiators

Features that set nazar-audit apart from the competition.

## P2.1 Guided Remediation

Prioritized fix suggestions inspired by OSV-Scanner's guided remediation:

For each fixable vulnerability, calculate and display:
- **ROI score** -- number of vulnerabilities fixed by upgrading a single direct dependency
- **Dependency depth** -- how deep in the tree the vulnerable package sits
- **Severity impact** -- total severity weight removed by the fix
- **Risk level** -- whether the fix is semver-compatible or requires a breaking change

Output a prioritized action list:

```
Recommended upgrades (sorted by impact):

1. Update express 4.17.1 -> 4.19.2
   Fixes: 3 vulnerabilities (1 high, 2 moderate)
   Risk: semver-compatible (minor version bump)

2. Update webpack 5.75.0 -> 5.90.3
   Fixes: 2 vulnerabilities (2 moderate)
   Risk: semver-compatible (patch version bump)

3. Update lodash 4.17.20 -> 4.17.21
   Fixes: 1 vulnerability (1 critical)
   Risk: semver-compatible (patch version bump)
   Note: also consider replacing lodash with native methods
```

## P2.2 Reachability Analysis

Determine whether the vulnerable code path is actually reachable from the project:

- Parse the project's import graph
- Trace whether the vulnerable package's affected function/module is imported
- Mark vulnerabilities as "reachable" or "unreachable" in the report
- Allow filtering to show only reachable vulnerabilities

This eliminates the majority of vulnerability noise -- most transitive dependencies' vulnerable code paths are never called.

## P2.3 Markdown Output

`--format markdown` produces a Markdown vulnerability summary suitable for:
- PR comments (via GitHub Actions)
- Team notifications (Slack, Teams)
- Documentation

## P2.4 Config in package.json

Support reading configuration from a `"nazar-audit"` key in `package.json`:

```json
{
  "nazar-audit": {
    "level": "high",
    "format": "table",
    "exceptions": [
      { "id": "GHSA-xxxx", "notes": "Not applicable" }
    ]
  }
}
```

This avoids an extra config file for simple setups.

## P2.5 SBOM Generation

Generate Software Bill of Materials in CycloneDX JSON or SPDX format:
- `--sbom cyclonedx` or `--sbom spdx`
- Includes all dependencies with versions, licenses, and known vulnerabilities
- Useful for compliance and supply chain visibility

## P2.6 License Compliance Scanning

Scan dependencies for license types and flag issues:
- `--license-allow <types>` -- allowlist (e.g., "MIT,Apache-2.0,ISC")
- `--license-deny <types>` -- denylist (e.g., "GPL-3.0")
- Report unknown or missing licenses
- Flag incompatible licenses

## P2.7 Programmatic API

Expose nazar-audit as an importable library:

```typescript
import { scan, formatReport } from 'nazar-audit'

const result = await scan({
  level: 'high',
  configPath: '.nazar.yml',
})

const json = formatReport(result, { format: 'json' })
const sarif = formatReport(result, { format: 'sarif' })
```

TypeScript-first with full type exports for integration into build tools, editors, and custom scripts.

## P2.8 Lockfile Integrity Validation

`nazar-audit lockfile` -- validate lockfile security:

- All `resolved` URLs use HTTPS
- All packages resolve to allowed registries
- Integrity hashes are present and use SHA-512
- Resolved URLs match expected package names
- Detect lockfile injection attacks

This addresses a blind spot that no npm audit wrapper currently covers.
