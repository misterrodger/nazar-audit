import type { ScanResult } from './types.js'
import { formatJson } from './report-json.js'

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

type JsonOutput = Record<string, unknown>

const parseOutput = (result: ScanResult): JsonOutput => JSON.parse(formatJson(result)) as JsonOutput

describe('formatJson', () => {
  it('produces valid JSON', () => {
    const output = formatJson(makeScanResult())

    expect(() => JSON.parse(output)).not.toThrow()
  })

  it('includes schemaVersion 1', () => {
    const parsed = parseOutput(makeScanResult())

    expect(parsed['schemaVersion']).toBe(1)
  })

  it('includes scanner name', () => {
    const parsed = parseOutput(makeScanResult())

    expect(parsed['scanner']).toBe('nazar-audit')
  })

  it('includes packageManager in metadata', () => {
    const parsed = parseOutput(makeScanResult({ packageManager: 'npm' }))
    const metadata = parsed['metadata'] as Record<string, unknown>

    expect(metadata['packageManager']).toBe('npm')
  })

  it('includes severity counts in metadata', () => {
    const result = makeScanResult({
      metadata: {
        ...makeScanResult().metadata,
        total: 3,
        severityCounts: { info: 0, low: 0, moderate: 1, high: 1, critical: 1 },
      },
    })
    const parsed = parseOutput(result)
    const metadata = parsed['metadata'] as Record<string, unknown>

    expect(metadata['severityCounts']).toStrictEqual({
      info: 0,
      low: 0,
      moderate: 1,
      high: 1,
      critical: 1,
    })
  })

  it('includes vulnerabilities array', () => {
    const parsed = parseOutput(makeScanResult())

    expect(parsed['vulnerabilities']).toStrictEqual([])
  })

  it('includes exceptions with matched, unused, and expired', () => {
    const parsed = parseOutput(makeScanResult())

    expect(parsed['exceptions']).toStrictEqual({
      matched: [],
      unused: [],
      expired: [],
    })
  })

  it('includes unhandled array', () => {
    const parsed = parseOutput(makeScanResult())

    expect(parsed['unhandled']).toStrictEqual([])
  })

  it('produces pretty-printed output with 2-space indent', () => {
    const output = formatJson(makeScanResult())

    expect(output).toContain('  "schemaVersion"')
  })
})
