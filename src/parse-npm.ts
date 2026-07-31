import {
  type Advisory,
  type FixAvailability,
  type Result,
  type Severity,
  type Vulnerability,
  SEVERITY_ORDER,
  ok,
  err,
} from './types.js'

type RawNpmAuditReport = Readonly<{
  auditReportVersion: number
  vulnerabilities: Readonly<Record<string, RawVulnerability>>
}>

type RawVulnerability = Readonly<{
  name: string
  severity: string
  isDirect: boolean
  via: ReadonlyArray<unknown>
  effects: ReadonlyArray<string>
  range: string
  nodes: ReadonlyArray<string>
  fixAvailable: boolean | RawFixObject
}>

type RawFixObject = Readonly<{
  name: string
  version: string
  isSemVerMajor: boolean
}>

type RawAdvisory = Readonly<{
  source: number
  name: string
  dependency: string
  title: string
  url: string
  severity: string
  cwe: ReadonlyArray<string>
  cvss: Readonly<{
    score: number
    vectorString: string | undefined
  }>
  range: string
}>

const isSeverity = (value: string): value is Severity =>
  (SEVERITY_ORDER as ReadonlyArray<string>).includes(value)

const isRawAdvisory = (entry: unknown): entry is RawAdvisory =>
  typeof entry === 'object' && !!entry && 'source' in entry && 'title' in entry

const parseAdvisory = (raw: RawAdvisory): Advisory => ({
  source: raw.source,
  name: raw.name,
  dependency: raw.dependency,
  title: raw.title,
  url: raw.url,
  severity: isSeverity(raw.severity) ? raw.severity : 'info',
  cwe: raw.cwe,
  cvss: {
    score: raw.cvss.score,
    vectorString: raw.cvss.vectorString ?? undefined,
  },
  range: raw.range,
})

const parseViaEntry = (entry: unknown): Advisory | string =>
  typeof entry === 'string' ? entry : isRawAdvisory(entry) ? parseAdvisory(entry) : String(entry)

const parseFixAvailable = (raw: boolean | RawFixObject): FixAvailability =>
  raw === false
    ? { kind: 'none' }
    : raw === true
      ? { kind: 'compatible' }
      : raw.isSemVerMajor
        ? { kind: 'breaking', name: raw.name, version: raw.version }
        : { kind: 'compatible' }

const parseVulnerability = (raw: RawVulnerability): Vulnerability => {
  const via = raw.via.map(parseViaEntry)
  const advisories = via.filter((v): v is Advisory => typeof v !== 'string')

  return {
    name: raw.name,
    severity: isSeverity(raw.severity) ? raw.severity : 'info',
    isDirect: raw.isDirect,
    via,
    effects: raw.effects,
    range: raw.range,
    nodes: raw.nodes,
    fixAvailable: parseFixAvailable(raw.fixAvailable),
    advisories,
  }
}

const isRawAuditReport = (data: unknown): data is RawNpmAuditReport =>
  typeof data === 'object' && !!data && 'auditReportVersion' in data && 'vulnerabilities' in data

export const parseNpmAuditJson = (jsonString: string): Result<ReadonlyArray<Vulnerability>> => {
  const parsed: unknown = JSON.parse(jsonString)

  return !isRawAuditReport(parsed)
    ? err('Invalid npm audit output: missing auditReportVersion or vulnerabilities field')
    : parsed.auditReportVersion !== 2
      ? err(
          `Unsupported audit report version: ${String(parsed.auditReportVersion)}. Only version 2 (npm v7+) is supported.`,
        )
      : ok(Object.values(parsed.vulnerabilities).map(parseVulnerability))
}
