# Architecture Decisions

Decisions made during the MVP planning session, preserved for future reference.

## D1. MVP package manager scope

**Decision:** npm-only. No multi-PM detection, no adapter abstraction.

**Rationale:** Designing an abstraction with exactly one implementation leads to the wrong abstraction. Ship the adapter interface when the second adapter (pnpm) arrives in Phase 1.

## D2. npm audit JSON schema version

**Decision:** v7+ only (`auditReportVersion: 2`). No v6 support.

**Rationale:** npm v6 went EOL in 2021. `engines` requires Node >= 18 which ships with npm v8+. No user on a supported Node version will encounter the v6 schema.

## D3. CLI framework

**Decision:** citty (from the UnJS ecosystem).

**Rationale:** ESM-native, functional-friendly API, lightweight. Commander uses classes and OOP patterns that fight the functional ESLint rules. `util.parseArgs` would mean hand-rolling help text and subcommands.

## D4. Exception config format

**Decision:** YAML only (`.nazar.yml`). No JSONC.

**Rationale:** One format, one parser, one set of tests. YAML is naturally more readable for exception lists with notes and expiry dates. The `yaml` package is tiny and well-maintained.

## D5. Runtime dependencies

**Decision:** Four runtime deps: `citty`, `yaml`, `picocolors`, `valibot`.

**Rationale:** Minimal footprint. picocolors (3KB) over chalk (280KB). Hand-rolled table over cli-table3. Valibot (6KB) over Zod (57KB) for config validation.

## D6. Config validation library

**Decision:** Valibot.

**Rationale:** Same parse-and-narrow pattern as Zod at 1/10th the size. For a CLI tool where bundle size matters and deps are kept minimal, Valibot is the right choice.

## D7. Exception matching -- identifier types

**Decision:** Three match types for MVP: GHSA ID, module name, numeric source.

**Rationale:** These cover the most common use cases. CWE matching, path matching, and partial URL matching add complexity without proportional value in the first release. Deferred to Phase 1.

## D8. Table output columns

**Decision:** Fixed default table: Severity, Module, Title, Fix, URL. No `--include-columns` configurability.

**Rationale:** Less config surface, ship faster. better-npm-audit had column configurability and it was rarely used. Add it in Phase 1 if users request it.

## D9. --filter-table default behavior

**Decision:** Show all severities by default. `--filter-table` is opt-in.

**Rationale:** Least surprising behavior. Users see the full picture. `--level` controls exit codes independently. If someone wants a quieter table, they explicitly pass `--filter-table`.

## D10. JSON output schema

**Decision:** Separate integer schema version (starts at 1). Normalized output only, no raw passthrough.

**Rationale:** Package version changes with every release; schema version changes only when the output structure changes. Normalized output is the value-add -- consumers of raw npm JSON can run `npm audit --json` directly.

## D11. Programmatic API

**Decision:** CLI-only MVP. No library exports until Phase 2.

**Rationale:** Exporting a programmatic API early commits to a public contract that is hard to change. Internal types need room to iterate. Add `exports`/`main` back when the API is deliberately designed.

## D12. Error handling strategy

**Decision:** `Result` type internally (`{ ok: true, data: T } | { ok: false, error: string }`). Single `try/catch` boundary in `cli.ts` with ESLint override.

**Rationale:** Keeps functional purity in the core while being pragmatic at the CLI boundary. All internal functions compose cleanly via Result types.

## D13. Testing strategy

**Decision:** Both fixture files and inline test data.

**Rationale:** Fixture files (real `npm audit --json` captures) for realistic end-to-end parsing. Inline data for edge cases (polymorphic shapes, missing fields). Track npm audit schema changes via [npm/cli CHANGELOG](https://github.com/npm/cli/blob/latest/CHANGELOG.md) and [npm RFCs](https://github.com/npm/rfcs).

## D14. --production flag

**Decision:** Passthrough to npm (`--omit=dev`).

**Rationale:** Post-filtering would require reconstructing the dependency graph, which npm does not provide cleanly. `isDirect` does not distinguish dev from prod. Keep it simple.

## D15. --registry flag

**Decision:** Deferred to Phase 1.

**Rationale:** Private registries are typically configured in `.npmrc`. This was the exact flag that caused the critical RCE in better-npm-audit. Deferring reduces scope and avoids the same vulnerability class.

## D16. CLI exception flags

**Decision:** `--ignore` / `-i` only (by advisory ID). Module-level ignoring via config file only.

**Rationale:** `--ignore` covers the most common use case: skip a specific advisory for this CI run. Module-level ignoring is a deliberate decision that belongs in the config file with documented reasoning.

## D17. Source file organization

**Decision:** Flat structure for MVP. Extract into folders when complexity grows.

**Rationale:** Helpers live with orchestrator until 2-3+ accumulate. The MVP has around 7 files. `Result` type lives in `types.ts`.

## D18. Config file discovery

**Decision:** CWD only. Missing config means zero exceptions, no error.

**Rationale:** Simplest behavior, matches where `npm audit` runs. Monorepo support (walking up) is a Phase 1 concern.

## D19. npm audit failure handling

**Decision:** Ignore npm exit code entirely. Parse stdout as JSON. Fail only if JSON is invalid.

**Rationale:** npm returns exit code 1 when vulnerabilities are found but the JSON is valid. Most tools get this wrong. Only care whether JSON parses successfully.

## D20. Build target

**Decision:** tsdown with `cli.ts` as sole entry point for MVP.

**Rationale:** Produces a single bundled `cli.js`. No library exports needed yet. Add `index.ts` as a second entry point in Phase 2.

## D21. Implementation order

**Decision:** Vertical slices: types/parser, exceptions, reporters, orchestrator, CLI, release.

**Rationale:** Each slice is independently testable and reviewable. The parser is the hardest piece -- get it right first with thorough tests.

## D22. --exclude flag naming

**Decision:** Renamed to `--ignore` / `-i`.

**Rationale:** Concise, matches audit-tool conventions. `--exclude` was too generic and could be confused with excluding packages.
