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

**Decision:** Fixed default table: Severity, Package, Title, Paths, Fix, URL. No `--include-columns` configurability.

**Rationale:** Less config surface, ship faster. "Paths" column shows shortened dependency chains (e.g. `pkg>dep`) for each advisory. "Module" renamed to "Package" for clarity. better-npm-audit had column configurability and it was rarely used. Add it in Phase 1 if users request it.

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

**Decision:** tsdown with `cli.ts` as sole entry point for MVP. Output is `dist/cli.mjs`.

**Rationale:** Produces a single bundled ESM file. No library exports needed yet. Add `index.ts` as a second entry point in Phase 2.

## D21. Implementation order

**Decision:** Vertical slices: types/parser, exceptions, reporters, orchestrator, CLI, release.

**Rationale:** Each slice is independently testable and reviewable. The parser is the hardest piece -- get it right first with thorough tests.

## D22. --exclude flag naming

**Decision:** Renamed to `--ignore` / `-i`.

**Rationale:** Concise, matches audit-tool conventions. `--exclude` was too generic and could be confused with excluding packages.

## D23. Banner output gating

**Decision:** Banner (nazar eye art) is only emitted for `--format table` output. Suppressed for `--format json`.

**Rationale:** Banner text written to stdout corrupts machine-parseable JSON output, breaking downstream tooling that pipes `nazar-audit --format json` into `jq` or similar.

## D24. npm audit timeout

**Decision:** Configurable via `--timeout <seconds>` CLI flag or `timeoutSeconds` config key. Default: 60 seconds. CLI flag takes precedence over config. The config key is named `timeoutSeconds` so users know the unit without reading documentation.

**Rationale:** 60 seconds covers the vast majority of CI pipelines. Large monorepos or slow registries may need more. `SIGTERM` is used as the kill signal so npm can clean up gracefully.

## D25. Severity breakdown counts

**Decision:** The severity breakdown in the table summary counts only unhandled (post-exception) vulnerabilities, not all discovered vulnerabilities.

**Rationale:** The summary should reflect what the user needs to act on. Counting excepted vulnerabilities in the breakdown contradicts the purpose of exceptions.

## D26. Terminal width in table output

**Decision:** `calculateWidths` accepts an optional `terminalWidth` parameter. When omitted, it reads `process.stdout.columns` with a fallback of 160.

**Rationale:** Injecting terminal width allows deterministic snapshot tests without environment-dependent column calculations. The 160-column default matches a wide terminal without line wrapping.

## D27. severityIndex deduplication

**Decision:** `severityIndex` lives in `types.ts` as a single exported function, imported by `scan.ts` and `report-table.ts`.

**Rationale:** Two identical copies of the same function is a maintenance hazard. Centralizing in `types.ts` next to `SEVERITY_ORDER` keeps the severity logic cohesive.

## D28. Test helpers -- Result narrowing

**Decision:** `expectOk` and `expectErr` in `test-helpers.ts` use `expect.unreachable()` with the discriminated union's own narrowing rather than `as` casts.

**Rationale:** Casts bypass the type system. After the `if (!result.ok)` guard, TypeScript narrows `result` to `{ ok: true; data: T }` naturally, so no cast is needed. `expect.unreachable()` provides a clear test failure message if the guard fails.

## D29. Scan spinner

**Decision:** `nanospinner` for the scanning progress indicator. Only shown for `--format table`.

**Rationale:** `nanospinner` (20 kB) depends on `picocolors`, which the project already uses -- zero new transitive dependencies. `yocto-spinner` would have added `yoctocolors` as a new dep tree. `ora` is 280 kB with many dependencies. The spinner is suppressed for JSON output to avoid corrupting machine-parseable output.

## D30. Unknown severity default

**Decision:** Unknown severity values from npm audit JSON are mapped to `critical` instead of `info`.

**Rationale:** A conservative approach -- if npm introduces a new severity level that nazar-audit does not recognize, treating it as critical ensures it surfaces to the user rather than being silently deprioritized.

## D31. --filter-table row-level filtering

**Decision:** `--filter-table` filters the rendered table rows by advisory severity, not by the parent vulnerability's rolled-up severity.

**Rationale:** A vulnerability may have a rolled-up severity of `high` but contain individual advisories at different severity levels. Filtering at the row level means what the user sees matches what was filtered.

## D32. Windows execFile compatibility

**Decision:** Pass `shell: true` to `execFileAsync` on Windows only.

**Rationale:** On Windows, npm is `npm.cmd` which requires a shell to execute. Without `shell: true`, `execFile` fails with ENOENT on Windows. The option is gated to Windows via `process.platform === 'win32'` to avoid unnecessary shell spawning on Unix.

## D33. Spinner lifecycle in error paths

**Decision:** The spinner variable is hoisted above the `try` block so it can be stopped in the `catch` handler.

**Rationale:** If an unexpected error occurs after the spinner is created but before normal error handling, the spinner would continue spinning indefinitely. Hoisting and stopping in `catch` ensures clean terminal output in all error paths.
