# AGENTS.md

Guidelines for AI agents working on this codebase.

## Project

**nazar-audit** is a CLI-only vulnerability scanner for the npm ecosystem. It wraps `npm audit --json` and adds exception management, multiple output formats, and fix availability reporting.

See [docs/decisions.md](docs/decisions.md) for all architectural decisions and their rationale.

## Architecture (MVP)

Flat file structure -- extract into folders when complexity grows (D17).

```
src/
  cli.ts              -- citty entry point, arg parsing, single try/catch boundary
  scan.ts             -- orchestrator: run audit, parse, apply exceptions, produce ScanResult
  parse-npm.ts        -- npm v7+ JSON -> Vulnerability[]
  exceptions.ts       -- YAML config loading, Valibot validation, matching, unused detection
  report-table.ts     -- fixed-column table with picocolors
  report-json.ts      -- normalized JSON output (schema version 1)
  types.ts            -- all types: Vulnerability, Advisory, FixAvailability, Result, etc.
```

## Key Design Decisions

- **CLI-only MVP** -- no library exports until Phase 2 (D11)
- **npm-only** -- no adapter abstraction until Phase 1 adds pnpm (D1)
- **npm v7+ JSON only** -- no v6 schema support (D2)
- **`execFile` not `exec`** -- no shell spawned, prevents command injection
- **Discriminated unions** for polymorphic data (`FixAvailability`, `ViaEntry`)
- **Result type** for error handling -- `{ ok: true, data: T } | { ok: false, error: string }` (D12)
- **Functional style** -- pure functions, composition, immutable data
- **`type` not `interface`** -- compose with `&` and `|`
- **`undefined` only, never `null`**
- **No `any`** -- use `unknown` and narrow

## Runtime Dependencies

Four total (D5): `citty` (CLI), `yaml` (config parsing), `picocolors` (terminal colors), `valibot` (config validation).

## TypeScript

- Strict mode with `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`
- TypeScript 7 (native Go compiler) for builds, TypeScript 6 side-by-side for eslint tooling
- Use `import type { ... }` for type-only imports
- Validate external data (npm audit JSON) with Valibot at the boundary; `@total-typescript/ts-reset` makes `JSON.parse` etc. return `unknown`
- Use `as const satisfies` for config objects
- `null` banned in lint -- use `undefined` only

## Testing

- **Vitest** for unit and integration tests
- Test files: `src/**/*.test.ts` (colocated)
- Fixture files for realistic npm audit JSON + inline data for edge cases (D13)
- Track npm audit schema changes via [npm/cli CHANGELOG](https://github.com/npm/cli/blob/latest/CHANGELOG.md) and [npm RFCs](https://github.com/npm/rfcs)

## Scripts

- `npm run ship` -- full quality gate: audit + depcheck + jscpd + license-check + format + lint + typecheck + build + test:coverage, then git commit and push
- `npm run publish:live` -- builds then publishes to npm
- `npm run depcheck` -- unused dependency detection via knip
- `npm run license-check` -- license compliance check via license-compliance
- `npm run jscpd` -- duplicate code detection

## Code Style

- No comments explaining what code does
- Descriptive function and variable names
- `const` over `let`
- Files and folders: kebab-case
- Functions: camelCase
- Types: PascalCase

## Common Tasks

### Adding a new output format

1. Create `src/report-<format>.ts`
2. Export a function that takes `ScanResult` and returns `string`
3. Wire it into the CLI's `--format` option in `cli.ts`
4. Add tests

### Adding a new exception match type

1. Add the match field to `ExceptionEntry` in `src/types.ts`
2. Add matching logic to `src/exceptions.ts`
3. Add tests covering the new match type

### Adding a new package manager (Phase 1+)

1. Extract adapter abstraction from `scan.ts` and `parse-npm.ts`
2. Create adapter for the new PM
3. Add lockfile detection
4. Add tests with fixture JSON from that package manager
