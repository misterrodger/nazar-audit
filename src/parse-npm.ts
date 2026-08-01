import * as v from 'valibot'
import {
  type Advisory,
  type FixAvailability,
  type Result,
  type ViaEntry,
  type Vulnerability,
  isSeverity,
  ok,
  err,
} from './types.js'

const RawCvssSchema = v.object({
  score: v.number(),
  vectorString: v.optional(v.nullable(v.string())),
})

const RawAdvisorySchema = v.object({
  source: v.number(),
  name: v.string(),
  dependency: v.string(),
  title: v.string(),
  url: v.string(),
  severity: v.string(),
  cwe: v.array(v.string()),
  cvss: RawCvssSchema,
  range: v.string(),
})

const RawFixObjectSchema = v.object({
  name: v.string(),
  version: v.string(),
  isSemVerMajor: v.boolean(),
})

const RawVulnerabilitySchema = v.object({
  name: v.string(),
  severity: v.string(),
  isDirect: v.boolean(),
  via: v.array(v.unknown()),
  effects: v.array(v.string()),
  range: v.string(),
  nodes: v.array(v.string()),
  fixAvailable: v.union([v.boolean(), RawFixObjectSchema]),
})

const RawNpmAuditReportSchema = v.object({
  auditReportVersion: v.number(),
  vulnerabilities: v.record(v.string(), RawVulnerabilitySchema),
})

type RawAdvisory = v.InferOutput<typeof RawAdvisorySchema>
type RawFixObject = v.InferOutput<typeof RawFixObjectSchema>
type RawVulnerability = v.InferOutput<typeof RawVulnerabilitySchema>

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

const parseViaEntry = (entry: unknown): ViaEntry | undefined => {
  const advisory = v.safeParse(RawAdvisorySchema, entry)

  return typeof entry === 'string' ? entry : advisory.success ? parseAdvisory(advisory.output) : undefined
}

const parseFixAvailable = (raw: boolean | RawFixObject): FixAvailability =>
  raw === false
    ? { kind: 'none' }
    : raw === true
      ? { kind: 'compatible' }
      : raw.isSemVerMajor
        ? { kind: 'breaking', name: raw.name, version: raw.version }
        : { kind: 'compatible' }

const parseVulnerability = (raw: RawVulnerability): Vulnerability => {
  const via = raw.via.map(parseViaEntry).filter((v): v is ViaEntry => v !== undefined)
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

const safeJsonParse = (jsonString: string): Result<unknown> => {
  // eslint-disable-next-line functional/no-try-statements -- JSON.parse is the only safe way to parse JSON
  try {
    return ok(JSON.parse(jsonString))
  } catch (e: unknown) {
    return err(`Failed to parse JSON: ${e instanceof Error ? e.message : String(e)}`)
  }
}

const parseReport = (data: unknown): Result<ReadonlyArray<Vulnerability>> => {
  const reportResult = v.safeParse(RawNpmAuditReportSchema, data)

  return !reportResult.success
    ? err(`Invalid npm audit output: ${reportResult.issues.map((i) => i.message).join(', ')}`)
    : reportResult.output.auditReportVersion !== 2
      ? err(
          `Unsupported audit report version: ${String(reportResult.output.auditReportVersion)}. Only version 2 (npm v7+) is supported.`,
        )
      : ok(Object.values(reportResult.output.vulnerabilities).map(parseVulnerability))
}

export const parseNpmAuditJson = (jsonString: string): Result<ReadonlyArray<Vulnerability>> => {
  const jsonResult = safeJsonParse(jsonString)

  return !jsonResult.ok ? jsonResult : parseReport(jsonResult.data)
}
