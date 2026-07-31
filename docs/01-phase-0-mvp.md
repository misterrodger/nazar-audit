# Phase 0: MVP

The minimum viable product -- everything needed for a useful first release.

## P0.1 Core Scanning Engine

Secure execution of the native package manager audit command.

- Use `execFile` (not `exec`) to spawn the audit process -- no shell interpretation, no command injection
- Validate any user-supplied arguments (e.g., `--registry` URL) before passing to the child process
- Buffer stdout as JSON, handle stderr for error reporting
- Auto-detect package manager from lockfile presence:
  - `package-lock.json` -> npm
  - `pnpm-lock.yaml` -> pnpm
  - `yarn.lock` -> yarn
  - `bun.lock` -> bun
- Max buffer size: 50 MB (large monorepo support)

## P0.2 npm v7+ JSON Parsing

Parse the audit report v2 schema (`auditReportVersion: 2`).

Key parsing challenges:
- `via` array is polymorphic: elements are either advisory objects (with `source`, `name`, `title`, `url`, `severity`, `cwe[]`, `cvss`) or bare package-name strings (meta-vulnerability pointers)
- `fixAvailable` is a three-shape union: `false`, `true`, or `{ name, version, isSemVerMajor }`
- Normalize both shapes into a clean internal `Vulnerability` type

Extract all fields:
- `name`, `severity`, `isDirect`, `range`, `nodes`, `effects`
- From advisory objects in `via`: `source`, `title`, `url`, `cwe[]`, `cvss.score`, `cvss.vectorString`
- `fixAvailable` normalized to a discriminated union

## P0.3 Exception Management

Config-file-driven exception management with `.nazar.yml` (or `.nazar.jsonc`):

```yaml
exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    active: true
    expiry: "2025-06-01"
    notes: "No impact -- we don't use the affected API"
    addedBy: "jrodger"

  - module: "minimist"
    notes: "Transitive dev-only dependency, not exposed"

  - id: "CVE-2024-1234"
    active: false
```

Features:
- Match by any identifier: numeric ID, GHSA, CVE, CWE, partial URL
- Module-level ignoring (all vulns from a specific package)
- `active` flag (default: true)
- `expiry` date with human-readable formats
- `notes` field for documenting why the exception exists
- `addedBy` field for accountability
- JSON Schema for IDE autocompletion and validation

CLI-based exceptions (override/supplement config file):
- `--exclude <ids>` -- comma-separated IDs
- `--module-ignore <names>` -- comma-separated module names

## P0.4 Unused Exception Detection

After matching exceptions against found vulnerabilities:
- Report any exception IDs that didn't match any vulnerability
- Report any ignored modules that had no matching vulnerabilities
- Suggest removal from the config file

## P0.5 Severity Threshold and Exit Codes

- `--level <info|low|moderate|high|critical>` -- minimum severity to trigger non-zero exit
- Exit code 0: no unhandled vulnerabilities above threshold
- Exit code 1: unhandled vulnerabilities found
- Exit code 2: scanner error (network, parse failure, invalid config)

Important: `--level` controls exit behavior only, not what's displayed. Use `--filter-table` to control display filtering independently.

## P0.6 Human-Readable Table Output

Colored, formatted table with configurable columns:

| Column | Description |
|---|---|
| ID | Advisory source ID |
| Module | Package name |
| Title | Advisory title |
| Severity | Colored + background-highlighted |
| URL | Link to advisory |
| Fix | Fix availability (yes/breaking/no) |
| Path | Shortened dependency path |
| Ex. | Whether the vuln is excepted (y/n) |

Features:
- `--include-columns <col1,col2,...>` to select visible columns
- `--filter-table [level]` to filter displayed rows by severity
- Severity background colors (red for critical/high, yellow for moderate)
- Dependency path shortening: `node_modules/a/node_modules/b` -> `a > b`
- Path truncation with "and N more..." for deeply nested deps

## P0.7 JSON Output

`--format json` produces normalized, structured JSON:

```json
{
  "version": "1.0.0",
  "scanner": "nazar-audit",
  "metadata": {
    "packageManager": "npm",
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

For each vulnerability, display fix information:

- **Available** -- `npm audit fix` can resolve it (semver-compatible)
- **Breaking** -- fix requires a major version bump of `<package>` to `<version>`
- **None** -- no fix available upstream

## P0.9 NO_COLOR Support

Respect the [no-color.org](https://no-color.org) standard:
- When `NO_COLOR` env var is set (any value), disable all ANSI color output
- Also disable colors when stdout is not a TTY

## P0.10 CLI

Full CLI with all options:

```
nazar-audit audit [options]

Options:
  -x, --exclude <ids>          Exception IDs to ignore (comma-separated)
  -m, --module-ignore <names>  Modules to ignore (comma-separated)
  -l, --level <severity>       Minimum severity for non-zero exit
  -f, --filter-table [level]   Filter table display by severity
  -p, --production             Skip devDependencies
      --format <type>          Output format: table, json (default: table)
      --registry <url>         Override registry URL
      --include-columns <cols> Columns to include in table
      --config <path>          Path to config file
  -V, --version                Show version
  -h, --help                   Show help
```
