import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Advisory, Result, ScanResult, Vulnerability } from './types/index.js'
import type { RawNpmAuditReport, RawVulnerability } from './parse-npm.js'
import { AUDIT_REPORT_VERSION } from './constants.js'

export const makeAdvisory = (overrides: Partial<Advisory> = {}): Advisory => ({
  source: 1001,
  name: 'testpkg',
  dependency: 'testpkg',
  title: 'Test Vulnerability',
  url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  severity: 'high',
  cwe: ['CWE-1'],
  cvss: { score: 7.5, vectorString: undefined },
  range: '<1.0.0',
  ...overrides,
})

export const makeVuln = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  name: 'testpkg',
  severity: 'high',
  isDirect: false,
  via: [],
  effects: [],
  range: '<1.0.0',
  nodes: ['node_modules/testpkg'],
  fixAvailable: { kind: 'none' },
  advisories: [makeAdvisory()],
  ...overrides,
})

export const makeMetadata = (
  overrides: Partial<ScanResult['metadata']> = {},
): ScanResult['metadata'] => ({
  total: 0,
  severityCounts: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
  directCount: 0,
  transitiveCount: 0,
  fixableCount: 0,
  unfixableCount: 0,
  ...overrides,
})

export const makeScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  packageManager: 'npm',
  vulnerabilities: [],
  metadata: makeMetadata(),
  exceptions: {
    matched: [],
    unused: [],
    expired: [],
  },
  unhandled: [],
  ...overrides,
})

const fixtureDir = join(import.meta.dirname, 'fixtures')
export const readFixture = (name: string): string => readFileSync(join(fixtureDir, name), 'utf-8')

const makeRawVia = (name: string): unknown[] => [
  {
    source: 1,
    name,
    dependency: name,
    title: 'Test vulnerability',
    url: 'https://github.com/advisories/GHSA-test-test-test',
    severity: 'high',
    cwe: ['CWE-1'],
    cvss: { score: 7.5, vectorString: 'CVSS:3.1/AV:N' },
    range: '<1.0.0',
  },
]

const makeRawVulnerability = (
  name: string,
  overrides: Partial<RawVulnerability> = {},
): RawVulnerability => ({
  name,
  severity: 'high',
  isDirect: false,
  via: makeRawVia(name),
  effects: [],
  range: '<1.0.0',
  nodes: [`node_modules/${name}`],
  fixAvailable: false,
  ...overrides,
})

export const makeRawAuditJson = (
  vulnerabilities: Record<string, Partial<RawVulnerability>> = { testpkg: {} },
): string =>
  JSON.stringify({
    auditReportVersion: AUDIT_REPORT_VERSION,
    vulnerabilities: Object.fromEntries(
      Object.entries(vulnerabilities).map(([name, overrides]) => [
        name,
        makeRawVulnerability(name, overrides),
      ]),
    ),
  } satisfies RawNpmAuditReport)

export const expectOk = <T>(result: Result<T>): T => {
  if (!result.ok) {
    expect.unreachable(`Expected ok but got error: ${result.error}`)
  }

  return result.data
}

export const expectErr = <T>(result: Result<T>): string => {
  if (result.ok) {
    expect.unreachable('Expected error but got ok')
  }

  return result.error
}
