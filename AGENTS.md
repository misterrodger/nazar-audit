# AGENTS.md

Guidelines for AI agents working on this codebase.

## Project

**nazar-audit** is a CLI vulnerability scanner for the JavaScript ecosystem. It wraps native package manager audit commands (npm, pnpm, yarn, bun) and adds exception management, multiple output formats, and fix availability reporting.

## Architecture

```
src/
  cli.ts              -- CLI entry point (bin), argument parsing
  index.ts            -- Public API exports for library consumers
  types/              -- Shared type definitions (Vulnerability, Advisory, Config, etc.)
  adapters/           -- Package manager adapters (npm, pnpm, yarn, bun)
  exceptions/         -- Config file parsing, exception matching, expiry validation
  reporters/          -- Output formatters (table, json, sarif, markdown)
  utils/              -- Shared utilities (color, date, common helpers)
```

## Key Design Decisions

- **Dual ESM/CJS** (`"type": "module"`, built with `tsdown` for both formats)
- **`execFile` not `exec`** -- no shell spawned, prevents command injection
- **Discriminated unions** for polymorphic data (`FixAvailability`, `ViaEntry`)
- **Functional style** -- pure functions, composition, immutable data
- **`type` not `interface`** -- compose with `&` and `|`
- **`undefined` only, never `null`**
- **No `any`** -- use `unknown` and narrow

## TypeScript

- Strict mode with `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`
- TypeScript 7 (native Go compiler) for builds, TypeScript 6 side-by-side for eslint tooling
- Use `import type { ... }` for type-only imports
- Validate external data (npm audit JSON) with runtime checks before casting; `@total-typescript/ts-reset` makes `JSON.parse` etc. return `unknown`
- Use `as const satisfies` for config objects
- Exhaustive switch via `assertNever`
- `null` banned in lint -- use `undefined` only

## Testing

- **Vitest** for unit and integration tests
- Test files: `src/**/*.test.ts`
- Mock npm audit JSON responses using fixtures in `tests/__fixtures__/`
- Test the parsing/normalization layer thoroughly -- the npm JSON schema is polymorphic and tricky

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

### Adding a new package manager adapter

1. Create `src/adapters/<pm>.ts`
2. Implement the `AuditAdapter` type (execute audit, normalize JSON output)
3. Add lockfile detection to `src/adapters/detect.ts`
4. Add tests with fixture JSON from that package manager

### Adding a new output format

1. Create `src/reporters/<format>.ts`
2. Implement the `Reporter` type (takes `ScanResult`, returns string)
3. Wire it into the CLI's `--format` option
4. Add tests

### Adding a new exception match type

1. Add the match field to `ExceptionEntry` in `src/types/`
2. Add matching logic to `src/exceptions/match.ts`
3. Add tests covering the new match type
