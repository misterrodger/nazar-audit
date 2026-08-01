export const SEVERITY_ORDER = ['info', 'low', 'moderate', 'high', 'critical'] as const

export type Severity = (typeof SEVERITY_ORDER)[number]

export type FixAvailability =
  | Readonly<{ kind: 'none' }>
  | Readonly<{ kind: 'compatible' }>
  | Readonly<{ kind: 'breaking'; name: string; version: string }>

export type Advisory = Readonly<{
  source: number
  name: string
  dependency: string
  title: string
  url: string
  severity: Severity
  cwe: ReadonlyArray<string>
  cvss: Readonly<{
    score: number
    vectorString: string | undefined
  }>
  range: string
}>

export type ViaEntry = Advisory | string

export type Vulnerability = Readonly<{
  name: string
  severity: Severity
  isDirect: boolean
  via: ReadonlyArray<ViaEntry>
  effects: ReadonlyArray<string>
  range: string
  nodes: ReadonlyArray<string>
  fixAvailable: FixAvailability
  advisories: ReadonlyArray<Advisory>
}>

export type ExceptionEntry = Readonly<{
  id?: string | undefined
  module?: string | undefined
  active?: boolean | undefined
  expiry?: string | undefined
  notes?: string | undefined
  addedBy?: string | undefined
}>

export type MatchedExceptionEntry = ExceptionEntry & Readonly<{ matchedVulnerability: string }>

export type NazarConfig = Readonly<{
  level?: Severity | undefined
  format?: 'table' | 'json' | undefined
  filterTable?: Severity | undefined
  production?: boolean | undefined
  timeoutSeconds?: number | undefined
  exceptions?: ReadonlyArray<ExceptionEntry> | undefined
}>

export type ScanResult = Readonly<{
  packageManager: string
  vulnerabilities: ReadonlyArray<Vulnerability>
  metadata: Readonly<{
    total: number
    severityCounts: Readonly<Record<Severity, number>>
    directCount: number
    transitiveCount: number
    fixableCount: number
    unfixableCount: number
  }>
  exceptions: Readonly<{
    matched: ReadonlyArray<MatchedExceptionEntry>
    unused: ReadonlyArray<ExceptionEntry>
    expired: ReadonlyArray<ExceptionEntry>
  }>
  unhandled: ReadonlyArray<Vulnerability>
}>

export type Result<T> = Readonly<{ ok: true; data: T }> | Readonly<{ ok: false; error: string }>

export const isSeverity = (value: string): value is Severity =>
  (SEVERITY_ORDER as ReadonlyArray<string>).includes(value)

export const severityIndex = (severity: Severity): number => SEVERITY_ORDER.indexOf(severity)

export const ok = <T>(data: T): Result<T> => ({ ok: true, data })

export const err = <T = never>(error: string): Result<T> => ({ ok: false, error })
