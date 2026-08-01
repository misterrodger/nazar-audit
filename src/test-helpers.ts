import type { Result, ScanResult, Vulnerability } from './types.js'

export const makeVuln = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  name: 'testpkg',
  severity: 'high',
  isDirect: false,
  via: [],
  effects: [],
  range: '<1.0.0',
  nodes: ['node_modules/testpkg'],
  fixAvailable: { kind: 'none' },
  advisories: [
    {
      source: 1001,
      name: 'testpkg',
      dependency: 'testpkg',
      title: 'Test Vulnerability',
      url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      severity: 'high',
      cwe: ['CWE-1'],
      cvss: { score: 7.5, vectorString: undefined },
      range: '<1.0.0',
    },
  ],
  ...overrides,
})

export const makeScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  packageManager: 'npm',
  vulnerabilities: [],
  metadata: {
    total: 0,
    severityCounts: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
    directCount: 0,
    transitiveCount: 0,
    fixableCount: 0,
    unfixableCount: 0,
  },
  exceptions: {
    matched: [],
    unused: [],
    expired: [],
  },
  unhandled: [],
  ...overrides,
})

export const expectOk = <T>(result: Result<T>): T => {
  expect(result.ok).toBe(true)

  return (result as { ok: true; data: T }).data
}

export const expectErr = <T>(result: Result<T>): string => {
  expect(result.ok).toBe(false)

  return (result as { ok: false; error: string }).error
}
