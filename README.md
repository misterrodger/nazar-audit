# nazar-audit

A modern, security-conscious package vulnerability scanner for the JavaScript ecosystem.

Named after the **nazar** -- the protective eye amulet found across the Mediterranean that wards off malicious intent.

[![CI](https://github.com/misterrodger/nazar-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/misterrodger/nazar-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/nazar-audit)](https://www.npmjs.com/package/nazar-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- Wraps native package manager audit (`npm`, `pnpm`, `yarn`, `bun`) with auto-detection
- **Exception management** with expiry dates, notes, and audit trail (`.nazar.yml`)
- **Multiple output formats**: table, JSON, SARIF (for GitHub Code Scanning)
- **Fix availability display** showing upgrade paths and breaking change warnings
- **Severity thresholds** that independently control exit behavior and table display
- **Module-level and path-level ignoring** with wildcard support
- **Secure by design** -- uses `execFile` (no shell), validates all inputs
- Zero/minimal runtime dependencies

## Installation

```bash
npm install -g nazar-audit
# or
npx nazar-audit audit
```

## Quick Start

```bash
# Run an audit
nazar-audit audit

# Set severity threshold
nazar-audit audit --level high

# Exclude specific advisories
nazar-audit audit --exclude GHSA-xxxx,CVE-2024-1234

# JSON output
nazar-audit audit --format json

# Filter table display while keeping full exit behavior
nazar-audit audit --level moderate --filter-table high
```

## Exception Management

Create a `.nazar.yml` file to manage exceptions:

```yaml
exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    expiry: "2025-06-01"
    notes: "No impact -- we don't use the affected API"

  - module: "minimist"
    notes: "Transitive dev-only dependency, not exposed"
```

nazar-audit warns about unused exceptions and expired entries.

## CLI Options

| Flag | Short | Description |
|---|---|---|
| `--exclude <ids>` | `-x` | Exception IDs to ignore (comma-separated) |
| `--module-ignore <names>` | `-m` | Modules to ignore (comma-separated) |
| `--level <severity>` | `-l` | Minimum severity for non-zero exit |
| `--filter-table [level]` | `-f` | Filter table display by severity |
| `--production` | `-p` | Skip devDependencies |
| `--format <type>` | | Output format: table, json, sarif |
| `--registry <url>` | `-r` | Override registry URL |
| `--include-columns <cols>` | `-i` | Columns to include in table |
| `--config <path>` | | Path to config file |
| `--fail-on <mode>` | | Exit behavior: all, upgradable, patchable |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No unhandled vulnerabilities above threshold |
| 1 | Unhandled vulnerabilities found |
| 2 | Scanner error (network, parse failure, invalid config) |

## Documentation

See the [docs](./docs) folder for the full roadmap and technical details:

- [Overview](./docs/00-overview.md)
- [Phase 0: MVP](./docs/01-phase-0-mvp.md)
- [Phase 1: High Value](./docs/02-phase-1-high-value.md)
- [Phase 2: Differentiators](./docs/03-phase-2-differentiators.md)
- [Phase 3: Aspirational](./docs/04-phase-3-aspirational.md)
- [Data Model](./docs/05-data-model.md)
- [Competitive Landscape](./docs/06-competitive-landscape.md)

## Development

```bash
npm install
npm run ship          # full quality gate: audit, depcheck, jscpd, license-check, format, lint, typecheck, build, test
npm run test:watch    # vitest in watch mode
npm run lint:fix      # auto-fix lint issues
npm run depcheck      # check for unused dependencies (knip)
npm run license-check # check dependency licenses
npm run jscpd         # check for duplicate code
```

## License

MIT
