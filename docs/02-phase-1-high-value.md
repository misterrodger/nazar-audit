# Phase 1: High Value

Features that significantly expand nazar-audit's utility and reach.

## P1.1 SARIF Output

SARIF 2.1.0 (Static Analysis Results Interchange Format) output for:
- GitHub Code Scanning integration (upload via `github/codeql-action/upload-sarif@v4`)
- Azure DevOps integration
- GitLab security reports
- Any SARIF-consuming platform

`--format sarif` produces a compliant SARIF file with:
- `tool.driver` identifying nazar-audit
- `rules` array mapping each advisory to a rule
- `results` array with severity, locations, and advisory URLs
- `partialFingerprints` for deduplication across runs

## P1.2 Dependency-Path-Specific Exceptions

Exception entries that only apply to a vulnerability when it arrives through a specific dependency chain:

```yaml
exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    path: "eslint>minimatch"
    notes: "Only affects linting, not production"
```

This allows ignoring a vulnerability in a dev tool's transitive dependency while still flagging it if it appears in a production dependency path.

## P1.3 Wildcard / Glob Patterns in Module Ignore

Support glob patterns in `--module-ignore` and config file module exceptions:

```yaml
exceptions:
  - module: "@types/*"
    notes: "Type-only packages, no runtime impact"
  - module: "eslint-*"
    notes: "Dev-only linting tools"
```

## P1.4 pnpm and Yarn Support

Package manager adapters for:
- **pnpm**: `pnpm audit --json`, parse pnpm's audit output format
- **Yarn Classic (v1)**: `yarn audit --json`, different schema with NDJSON output
- **Yarn Berry (v2+)**: `yarn npm audit --json`, different flags (`--severity`, `--environment`, `--exclude`)
- **Bun**: `bun audit --json` (if/when available)

Each adapter normalizes its output to the shared `Vulnerability` type.

## P1.5 Interactive Exception Workflow

`nazar-audit resolve` -- an interactive mode for triaging vulnerabilities:

For each unresolved vulnerability:
1. Display full details (severity, title, URL, fix availability, dependency path)
2. Offer options:
   - **Fix** -- run `<pm> audit fix` for this package
   - **Ignore** (with expiry) -- add to config with a date
   - **Ignore** (permanent) -- add to config with reason
   - **Skip** -- move to next
   - **Quit** -- exit
3. Write decisions to `.nazar.yml` with timestamps

Auto-suggest `<pm> audit fix` for fixable issues before asking about ignoring.

## P1.6 Delta Reporting

Compare current scan against a previous scan result:
- `--baseline <path>` to specify a previous JSON output file
- Report new vulnerabilities (not in baseline)
- Report resolved vulnerabilities (in baseline but not current)
- Report unchanged vulnerabilities
- Useful for CI to detect regressions vs. known state

## P1.7 Fail-On Mode

**Status:** Implemented.

Snyk-style exit code control:
- `--fail-on all` -- fail on any vulnerability (default)
- `--fail-on upgradable` -- fail only when a semver-compatible fix exists
- `--fail-on patchable` -- fail only when any fix exists (including breaking)

Useful for CI pipelines that want to enforce fixing what's fixable without blocking on unfixable transitive vulnerabilities.

## P1.8 Retry Logic

`--retry-count <n>` (default: 3) -- retry audit API calls on network failure.

Handles flaky registry responses in CI environments without failing the build.

`--pass-enoaudit` -- exit 0 if the audit registry is completely unreachable (like audit-ci).

## P1.9 Dev / Optional Dependency Filtering

- `--omit <dev|optional|peer>` -- exclude dependency types from the audit
- `--include <prod|dev|optional|peer>` -- override `--omit`
- `--production` shorthand for `--omit dev`
- `--ignore-optional` -- skip optional dependency vulnerabilities

## P1.10 Workspace / Monorepo Support

- `--workspace <name>` -- audit a specific workspace
- `--workspaces` -- audit all workspaces
- `--include-workspace-root` -- include the root project
- Support npm workspaces, pnpm workspaces, and Yarn workspaces

## P1.11 CLI Branding Art

**Status:** Implemented in P0.11.

Unicode nazar eye art displayed at startup, with version text. Colors via `picocolors`, respects `NO_COLOR`.
