import { formatJson } from './report-json.js'
import { makeScanResult, makeMetadata } from './test-helpers.js'

type JsonOutput = Record<string, unknown>

const parseOutput = (json: string): JsonOutput => JSON.parse(json) as JsonOutput

describe('formatJson', () => {
  it('produces valid JSON', () => {
    const output = formatJson(makeScanResult())

    expect(() => JSON.parse(output)).not.toThrow()
  })

  it('includes schemaVersion 1', () => {
    const parsed = parseOutput(formatJson(makeScanResult()))

    expect(parsed['schemaVersion']).toBe(1)
  })

  it('includes scanner name', () => {
    const parsed = parseOutput(formatJson(makeScanResult()))

    expect(parsed['scanner']).toBe('nazar-audit')
  })

  it('includes packageManager in metadata', () => {
    const parsed = parseOutput(formatJson(makeScanResult({ packageManager: 'npm' })))
    const metadata = parsed['metadata'] as Record<string, unknown>

    expect(metadata['packageManager']).toBe('npm')
  })

  it('includes severity counts in metadata', () => {
    const result = makeScanResult({
      metadata: makeMetadata({
        total: 3,
        severityCounts: { info: 0, low: 0, moderate: 1, high: 1, critical: 1 },
      }),
    })
    const parsed = parseOutput(formatJson(result))
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
    const parsed = parseOutput(formatJson(makeScanResult()))

    expect(parsed['vulnerabilities']).toStrictEqual([])
  })

  it('includes exceptions with matched, unused, and expired', () => {
    const parsed = parseOutput(formatJson(makeScanResult()))

    expect(parsed['exceptions']).toStrictEqual({
      matched: [],
      unused: [],
      expired: [],
    })
  })

  it('includes unhandled array', () => {
    const parsed = parseOutput(formatJson(makeScanResult()))

    expect(parsed['unhandled']).toStrictEqual([])
  })

  it('produces pretty-printed output with 2-space indent', () => {
    const output = formatJson(makeScanResult())

    expect(output).toContain('  "schemaVersion"')
  })
})
