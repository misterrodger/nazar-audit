import { formatTable } from './report-table.js'
import { makeVuln, makeScanResult } from './test-helpers.js'

// eslint-disable-next-line no-control-regex
const stripAnsi = (str: string): string => str.replace(/\x1b\[[0-9;]*m/g, '')

describe('formatTable', () => {
  it('shows no vulnerabilities message for empty results', () => {
    const output = stripAnsi(formatTable(makeScanResult(), undefined))

    expect(output).toContain('No vulnerabilities found.')
  })

  it('renders header row with correct column names', () => {
    const result = makeScanResult({
      unhandled: [makeVuln()],
      metadata: {
        ...makeScanResult().metadata,
        total: 1,
        severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
      },
    })
    const output = stripAnsi(formatTable(result, undefined))

    expect(output).toContain('Severity')
    expect(output).toContain('Package')
    expect(output).toContain('Title')
    expect(output).toContain('Fix')
    expect(output).toContain('URL')
  })

  it('renders vulnerability data in table rows', () => {
    const result = makeScanResult({
      unhandled: [makeVuln()],
      metadata: {
        ...makeScanResult().metadata,
        total: 1,
        severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
      },
    })
    const output = stripAnsi(formatTable(result, undefined))

    expect(output).toContain('high')
    expect(output).toContain('testpkg')
    expect(output).toContain('Test Vulnerability')
    expect(output).toContain('No')
    expect(output).toContain('GHSA-aaaa-bbbb-cccc')
  })

  it('sorts vulnerabilities by severity descending', () => {
    const result = makeScanResult({
      unhandled: [
        makeVuln({
          name: 'low-pkg',
          severity: 'low',
          advisories: [{ ...makeVuln().advisories[0]!, severity: 'low', title: 'Low vuln' }],
        }),
        makeVuln({
          name: 'crit-pkg',
          severity: 'critical',
          advisories: [
            { ...makeVuln().advisories[0]!, severity: 'critical', title: 'Critical vuln' },
          ],
        }),
      ],
      metadata: {
        ...makeScanResult().metadata,
        total: 2,
        severityCounts: { info: 0, low: 1, moderate: 0, high: 0, critical: 1 },
      },
    })
    const output = stripAnsi(formatTable(result, undefined))
    const criticalIndex = output.indexOf('Critical vuln')
    const lowIndex = output.indexOf('Low vuln')

    expect(criticalIndex).toBeLessThan(lowIndex)
  })

  describe('fix availability display', () => {
    it('shows Yes for compatible fix', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ fixAvailable: { kind: 'compatible' } })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Yes')
    })

    it('shows Breaking with package info for breaking fix', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({ fixAvailable: { kind: 'breaking', name: 'parent', version: '2.0.0' } }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Breaking (parent@2.0.0)')
    })

    it('shows No when no fix available', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ fixAvailable: { kind: 'none' } })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('No')
    })
  })

  describe('--filter-table', () => {
    it('filters vulnerabilities below the specified severity', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            name: 'high-pkg',
            severity: 'high',
            advisories: [{ ...makeVuln().advisories[0]!, title: 'High vuln' }],
          }),
          makeVuln({
            name: 'low-pkg',
            severity: 'low',
            advisories: [{ ...makeVuln().advisories[0]!, severity: 'low', title: 'Low vuln' }],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 2,
          severityCounts: { info: 0, low: 1, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, 'high'))

      expect(output).toContain('High vuln')
      expect(output).not.toContain('Low vuln')
    })

    it('shows filter-aware message when filter excludes all', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ severity: 'low' })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 1, moderate: 0, high: 0, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, 'critical'))

      expect(output).toContain('No vulnerabilities at or above critical severity.')
    })
  })

  describe('meta-vulnerabilities', () => {
    it('shows via package name for string-only via entries', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['upstream-pkg'] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('via upstream-pkg')
    })
  })

  describe('summary', () => {
    it('shows total vulnerability count', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 3,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 3, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 1 package with vulnerabilities')
    })

    it('shows unused exception warning', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
        exceptions: { matched: [], unused: [{ id: 'GHSA-orphan' }], expired: [] },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 unused exception(s)')
    })

    it('shows expired exception warning', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
        exceptions: {
          matched: [],
          unused: [],
          expired: [{ id: 'GHSA-old', expiry: '2020-01-01' }],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 expired exception(s)')
    })
  })
})
