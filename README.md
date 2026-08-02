# nazar-audit

A modern, security-conscious package vulnerability scanner for the JavaScript ecosystem.

Named after the **nazar** -- the protective eye amulet found across the Mediterranean that wards off malicious intent.

[![CI](https://github.com/misterrodger/nazar-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/misterrodger/nazar-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/nazar-audit)](https://www.npmjs.com/package/nazar-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- Wraps `npm audit --json` with structured output and exit code control
- **Exception management** with expiry dates, notes, and audit trail (`.nazar.yml`)
- **Multiple output formats**: colored table with severity breakdown, normalized JSON
- **Dependency paths** showing the full chain for each advisory
- **Fix availability display** showing upgrade paths and breaking change warnings
- **Severity thresholds** that independently control exit behavior and table display
- **Secure by design** -- uses `execFile` (no shell injection), validates all external data with Valibot
- **Windows compatible** -- handles `npm.cmd` shims automatically
- Five runtime dependencies: `citty`, `yaml`, `picocolors`, `valibot`, `nanospinner`

## Installation

```bash
npm install -g nazar-audit
# or
npx nazar-audit
```

## Quick Start

```bash
# Run an audit
nazar-audit

# Set severity threshold (exit non-zero only for high+)
nazar-audit --level high

# Ignore specific advisories
nazar-audit --ignore GHSA-xxxx,CVE-2024-1234

# JSON output (suppresses banner and spinner)
nazar-audit --format json

# Filter table display while keeping full exit behavior
nazar-audit --level moderate --filter-table high

# Skip devDependencies
nazar-audit --production

# Custom timeout for slow registries
nazar-audit --timeout 120
```

## Configuration

Create a `.nazar.yml` file in your project root to manage exceptions and defaults:

```yaml
# Minimum severity for non-zero exit
level: high

# npm audit timeout in seconds (default: 60)
timeoutSeconds: 120

# Skip devDependencies
production: false

exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    expiry: "2025-06-01"
    notes: "No impact -- we don't use the affected API"
    addedBy: "jrodger"

  - module: "minimist"
    notes: "Dev-only transitive dependency, not exposed"

  - id: "CVE-2024-1234"
    active: false
    notes: "Re-enabled after patch lands"
```

nazar-audit warns about unused exceptions and expired entries in the output.

## CLI Options

| Flag | Alias | Description |
|---|---|---|
| `--level <severity>` | `-l` | Minimum severity for non-zero exit (`info`, `low`, `moderate`, `high`, `critical`) |
| `--filter-table <severity>` | | Only show rows at or above this severity in the table |
| `--format <type>` | `-f` | Output format: `table` (default) or `json` |
| `--ignore <ids>` | `-i` | Advisory IDs to ignore (comma-separated GHSA/CVE) |
| `--production` | `-p` | Pass `--omit=dev` to npm audit |
| `--timeout <seconds>` | | npm audit timeout in seconds (default: 60) |
| `--config <path>` | | Path to `.nazar.yml` config file |

CLI flags take precedence over config file values.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No unhandled vulnerabilities above threshold |
| 1 | Unhandled vulnerabilities found |
| 2 | Scanner error (network, parse failure, invalid config) |

## Requirements

- Node.js >= 22.0.0
- npm >= 8 (ships with Node 18+)

## Documentation

See the [docs](./docs) folder for the full roadmap and technical details:

- [Overview](./docs/00-overview.md)
- [Phase 0: MVP](./docs/01-phase-0-mvp.md)
- [Phase 1: High Value](./docs/02-phase-1-high-value.md)
- [Phase 2: Differentiators](./docs/03-phase-2-differentiators.md)
- [Phase 3: Aspirational](./docs/04-phase-3-aspirational.md)
- [Data Model](./docs/05-data-model.md)
- [Competitive Landscape](./docs/06-competitive-landscape.md)
- [Architecture Decisions](./docs/decisions.md)

## Development

```bash
npm install
npm run ship             # full quality gate: audit, depcheck, jscpd, license-check, format, lint, typecheck, build, test
npm run test:watch       # vitest in watch mode
npm run test:coverage    # vitest with coverage report
npm run test:mutation    # stryker mutation testing
npm run lint:fix         # auto-fix lint issues
npm run depcheck         # check for unused dependencies (knip)
npm run license-check    # check dependency licenses
npm run jscpd            # check for duplicate code
```

## License

MIT
