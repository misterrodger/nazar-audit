# Phase 0: MVP

The minimum viable product -- everything needed for a useful first release.

**Status:** Implemented in v0.1.0.

## P0.1 Core Scanning Engine

Secure execution of `npm audit --json`.

- Uses `execFile` (not `exec`) to spawn the audit process -- no shell interpretation, no command injection
- Buffers stdout as JSON, reports stderr for error messages
- npm-only in MVP; multi-package-manager support planned for Phase 1
- Max buffer size: 50 MB (large monorepo support)
- Windows support via `npm.cmd`

## P0.2 npm v7+ JSON Parsing

Parses the audit report v2 schema (`auditReportVersion: 2`), validated with Valibot.

Key parsing challenges:
- `via` array is polymorphic: elements are either advisory objects (with `source`, `name`, `title`, `url`, `severity`, `cwe[]`, `cvss`) or bare package-name strings (meta-vulnerability pointers)
- `fixAvailable` is a three-shape union: `false`, `true`, or `{ name, version, isSemVerMajor }`
- Both shapes are normalized into a clean internal `Vulnerability` type
- Invalid `via` entries are silently dropped rather than coerced

Extracted fields:
- `name`, `severity`, `isDirect`, `range`, `nodes`, `effects`
- From advisory objects in `via`: `source`, `title`, `url`, `cwe[]`, `cvss.score`, `cvss.vectorString`
- `fixAvailable` normalized to a discriminated union (`none | compatible | breaking`)

## P0.3 Exception Management

Config-file-driven exception management via `.nazar.yml`:

```yaml
exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    active: true
    expiry: "2025-06-01"
    notes: "No impact -- we don't use the affected API"

  - id: "CVE-2024-1234"
    active: false
```

Features:
- Match by GHSA ID, CVE ID, or numeric advisory source ID
- ID matching extracts the tail from advisory URLs for exact comparison
- `active` flag (default: true)
- `expiry` date (ISO 8601) -- expired exceptions are reported
- `notes` field for documenting why the exception exists
- Config validated with Valibot schemas

CLI-based exceptions (supplement config file):
- `--ignore <ids>` -- comma-separated IDs

Explicit config path:
- `--config <path>` -- load config from a specific file path

## P0.4 Unused Exception Detection

After matching exceptions against found vulnerabilities:
- Reports exception IDs that didn't match any vulnerability
- Reports expired exceptions separately

## P0.5 Severity Threshold and Exit Codes

- `--level <info|low|moderate|high|critical>` -- minimum severity to trigger non-zero exit
- Exit code 0: no unhandled vulnerabilities above threshold
- Exit code 1: unhandled vulnerabilities found
- Exit code 2: scanner error (network, parse failure, invalid config, invalid CLI args)

Important: `--level` controls exit behavior only, not what's displayed. Use `--filter-table` to control display filtering independently.

## P0.6 Human-Readable Table Output

Colored, fixed-column table with dynamic width:

| Column | Description |
|---|---|
| ID | Advisory source ID |
| Package | Package name |
| Title | Advisory title (word-wrapped to available width) |
| Severity | Colored severity label |
| URL | Link to advisory |
| Fix | Fix availability (yes/breaking/no) |

Features:
- `--filter-table <severity>` to filter displayed rows by severity
- Dynamic title column width based on terminal width
- Advisories deduplicated by URL to avoid duplicate rows
- Severity tally with colored counts
- Summary shows unique package count ("Found X packages with vulnerabilities")
- Filter-aware empty message when severity filter hides all results
- `NO_COLOR` / non-TTY detection via `picocolors`

## P0.7 JSON Output

`--format json` produces normalized, structured JSON:

```json
{
  "version": "1.0.0",
  "scanner": "nazar-audit",
  "metadata": {
    "totalVulnerabilities": 5,
    "severityCounts": { "critical": 1, "high": 2, "moderate": 2 },
    "exceptedCount": 1,
    "unhandledCount": 4
  },
  "vulnerabilities": [...],
  "exceptions": {
    "matched": [...],
    "unused": [...]
  }
}
```

## P0.8 Fix Availability Display

For each vulnerability, the table shows fix information:

- **yes** -- `npm audit fix` can resolve it (semver-compatible)
- **breaking** -- fix requires a major version bump of `<package>` to `<version>`
- **no** -- no fix available upstream

## P0.9 NO_COLOR Support

Respects the [no-color.org](https://no-color.org) standard via `picocolors`:
- When `NO_COLOR` env var is set, ANSI color output is disabled
- Colors also disabled when stdout is not a TTY

## P0.10 CLI

```
nazar-audit [options]

Options:
  --level <severity>       Minimum severity for non-zero exit
  --filter-table <severity> Filter table display by severity
  --format <type>          Output format: table, json (default: table)
  --ignore <ids>           Advisory IDs to ignore (comma-separated)
  --production             Pass --omit=dev to npm audit
  --config <path>          Path to .nazar.yml config file
  --version                Show version
  --help                   Show help
```

## P0.11 CLI Branding

Unicode nazar eye art displayed at startup, with version text. Colors applied via `picocolors` and respect `NO_COLOR`.
