# Data Model

The internal vulnerability model that all package manager adapters produce and all reporters consume.

## Vulnerability Type

```typescript
type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical'

type FixAvailability =
  | { kind: 'none' }
  | { kind: 'compatible' }
  | { kind: 'breaking'; name: string; version: string }

type Advisory = {
  readonly source: number
  readonly name: string
  readonly dependency: string
  readonly title: string
  readonly url: string
  readonly severity: Severity
  readonly cwe: readonly string[]
  readonly cvss: {
    readonly score: number
    readonly vectorString: string | undefined
  }
  readonly range: string
}

type Vulnerability = {
  readonly name: string
  readonly severity: Severity
  readonly isDirect: boolean
  readonly via: readonly (Advisory | string)[]
  readonly effects: readonly string[]
  readonly range: string
  readonly nodes: readonly string[]
  readonly fixAvailable: FixAvailability
  readonly advisories: readonly Advisory[]
}
```

## npm Audit v7+ JSON Mapping

The npm audit `--json` output (schema v2, `auditReportVersion: 2`) maps to the internal model as follows:

| npm JSON Field | Internal Field | Notes |
|---|---|---|
| `vulnerabilities[name].name` | `Vulnerability.name` | Direct mapping |
| `vulnerabilities[name].severity` | `Vulnerability.severity` | Direct mapping |
| `vulnerabilities[name].isDirect` | `Vulnerability.isDirect` | Direct mapping |
| `vulnerabilities[name].via[]` | `Vulnerability.via` | Polymorphic: advisory objects or string pointers |
| `vulnerabilities[name].effects[]` | `Vulnerability.effects` | Direct mapping |
| `vulnerabilities[name].range` | `Vulnerability.range` | Direct mapping |
| `vulnerabilities[name].nodes[]` | `Vulnerability.nodes` | Direct mapping |
| `vulnerabilities[name].fixAvailable` | `Vulnerability.fixAvailable` | Normalize three-shape union |

### Parsing `via` entries

Each element in `via` is either:

1. **Advisory object** -- contains `source`, `name`, `dependency`, `title`, `url`, `severity`, `cwe[]`, `cvss.score`, `cvss.vectorString`, `range`
2. **String** -- a package name pointing to another key in the `vulnerabilities` map (meta-vulnerability)

Parse with a type guard that discriminates on `typeof via[i]`:

```typescript
const parseViaEntry = (entry: unknown): Advisory | string =>
  typeof entry === 'string' ? entry : parseAdvisory(entry)
```

### Normalizing `fixAvailable`

The raw npm field has three shapes:

| Raw value | Normalized |
|---|---|
| `false` | `{ kind: 'none' }` |
| `true` | `{ kind: 'compatible' }` |
| `{ name, version, isSemVerMajor: true }` | `{ kind: 'breaking', name, version }` |
| `{ name, version, isSemVerMajor: false }` | `{ kind: 'compatible' }` |

## Exception Config Schema

```typescript
type ExceptionEntry = {
  readonly id?: string
  readonly module?: string
  readonly path?: string
  readonly active?: boolean       // default: true
  readonly expiry?: string        // ISO date or human-readable
  readonly notes?: string
  readonly addedBy?: string
}

// Implemented
type NazarConfig = {
  readonly level?: Severity
  readonly failOn?: 'all' | 'upgradable' | 'patchable'
  readonly format?: 'table' | 'json'
  readonly filterTable?: Severity
  readonly production?: boolean
  readonly timeoutSeconds?: number
  readonly exceptions?: readonly ExceptionEntry[]
}

// Planned (Phase 1+) -- not yet in src/types/index.ts
//   includeColumns: readonly string[]  -- D8 deferred column configurability
//   registry: string                  -- D15, deferred pending RCE-safety review
//   retryCount: number                -- P1.8
//   passEnoaudit: boolean             -- P1.8
//   format: 'sarif' | 'markdown'      -- P1.1
```

## Scan Result Type

```typescript
type ScanResult = {
  readonly packageManager: string
  readonly vulnerabilities: readonly Vulnerability[]
  readonly metadata: {
    readonly total: number
    readonly severityCounts: Record<Severity, number>
    readonly directCount: number
    readonly transitiveCount: number
    readonly fixableCount: number
    readonly unfixableCount: number
  }
  readonly exceptions: {
    readonly matched: readonly MatchedExceptionEntry[]
    readonly unused: readonly ExceptionEntry[]
    readonly expired: readonly ExceptionEntry[]
  }
  readonly unhandled: readonly Vulnerability[]
}
```

## npm Audit v6 JSON Mapping (Legacy)

npm v6 uses `advisories` instead of `vulnerabilities`:

| npm v6 Field | Internal Field | Notes |
|---|---|---|
| `advisories[id].id` | `Advisory.source` | Numeric ID |
| `advisories[id].module_name` | `Vulnerability.name` | |
| `advisories[id].title` | `Advisory.title` | |
| `advisories[id].severity` | `Vulnerability.severity` | |
| `advisories[id].url` | `Advisory.url` | |
| `advisories[id].cves[]` | Mapped to `Advisory.cwe` equivalent | CVEs not CWEs in v6 |
| `advisories[id].cwe` | `Advisory.cwe` | Single CWE string |
| `advisories[id].findings[].paths[]` | `Vulnerability.nodes` | |

Detect schema version by checking for `auditReportVersion` field:
- Present and `2` -> v7+ schema
- Absent -> v6 schema (check for `advisories` key)
