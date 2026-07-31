import { type ScanResult, type Vulnerability } from './types.js'
import { meetsThreshold } from './scan.js'

const makeVuln = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  name: 'testpkg',
  severity: 'high',
  isDirect: false,
  via: [],
  effects: [],
  range: '<1.0.0',
  nodes: ['node_modules/testpkg'],
  fixAvailable: { kind: 'none' },
  advisories: [],
  ...overrides,
})

const makeScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
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

describe('meetsThreshold', () => {
  it('passes when no unhandled vulnerabilities', () => {
    expect(meetsThreshold(makeScanResult(), 'low')).toBe(true)
  })

  it('fails when unhandled vulnerability meets threshold', () => {
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'high' })],
    })

    expect(meetsThreshold(result, 'high')).toBe(false)
  })

  it('passes when unhandled vulnerability is below threshold', () => {
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' })],
    })

    expect(meetsThreshold(result, 'high')).toBe(true)
  })

  it('fails when any unhandled vulnerability meets threshold', () => {
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' }), makeVuln({ severity: 'critical' })],
    })

    expect(meetsThreshold(result, 'high')).toBe(false)
  })

  it('defaults to low threshold when level is undefined', () => {
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' })],
    })

    expect(meetsThreshold(result, undefined)).toBe(false)
  })

  it('passes info-level vulns when threshold is low', () => {
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'info' })],
    })

    expect(meetsThreshold(result, 'low')).toBe(true)
  })

  it.each([
    { severity: 'critical', level: 'critical', expected: false },
    { severity: 'high', level: 'critical', expected: true },
    { severity: 'moderate', level: 'high', expected: true },
    { severity: 'moderate', level: 'moderate', expected: false },
    { severity: 'low', level: 'low', expected: false },
    { severity: 'info', level: 'info', expected: false },
  ] as const)(
    'severity=$severity level=$level => passes=$expected',
    ({ severity, level, expected }) => {
      const result = makeScanResult({
        unhandled: [makeVuln({ severity })],
      })

      expect(meetsThreshold(result, level)).toBe(expected)
    },
  )
})
