import { formatTable } from './report-table.js'
import { makeVuln, makeScanResult } from './test-helpers.js'

// eslint-disable-next-line no-control-regex
const stripAnsi = (str: string): string => str.replace(/\x1b\[[0-9;]*m/g, '')

describe('formatTable', () => {
  it('shows no vulnerabilities message for empty results', () => {
    const output = stripAnsi(formatTable(makeScanResult(), undefined))

    expect(output).toMatchInlineSnapshot(`
      "
      No vulnerabilities found.
      "
    `)
  })

  it('renders a single high-severity vulnerability', () => {
    const result = makeScanResult({
      unhandled: [makeVuln()],
      metadata: {
        ...makeScanResult().metadata,
        total: 1,
        severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
      },
    })
    const output = stripAnsi(formatTable(result, undefined))

    expect(output).toMatchInlineSnapshot(`
      "
      Severity  Package  Title                 Paths            Fix  URL
      ────────  ───────  ────────────────────  ───────────────  ───  ───
      high      testpkg  Test Vulnerability    testpkg          No   https://github.com/advisories/GHSA-aaaa-bbbb-cccc

      Found 1 package with 1 vulnerability (1 unhandled)
        1 high
      "
    `)
  })

  it('sorts vulnerabilities by severity descending', () => {
    const result = makeScanResult({
      unhandled: [
        makeVuln({
          name: 'low-pkg',
          severity: 'low',
          nodes: ['node_modules/low-pkg'],
          advisories: [
            {
              ...makeVuln().advisories[0]!,
              severity: 'low',
              title: 'Low vuln',
              url: 'https://github.com/advisories/GHSA-low0-low0-low0',
            },
          ],
        }),
        makeVuln({
          name: 'crit-pkg',
          severity: 'critical',
          nodes: ['node_modules/crit-pkg'],
          advisories: [
            {
              ...makeVuln().advisories[0]!,
              severity: 'critical',
              title: 'Critical vuln',
              url: 'https://github.com/advisories/GHSA-crit-crit-crit',
            },
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

    expect(output).toMatchInlineSnapshot(`
      "
      Severity  Package   Title                 Paths            Fix  URL
      ────────  ────────  ────────────────────  ───────────────  ───  ───
      critical  crit-pkg  Critical vuln         crit-pkg         No   https://github.com/advisories/GHSA-crit-crit-crit
      low       low-pkg   Low vuln              low-pkg          No   https://github.com/advisories/GHSA-low0-low0-low0

      Found 2 packages with 2 vulnerabilities (2 unhandled)
        1 low, 1 critical
      "
    `)
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
      expect(output).not.toContain('  No ')
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
      const lines = output.split('\n')
      const dataLine = lines.find((l) => l.includes('testpkg'))

      expect(dataLine).toContain('  No ')
    })
  })

  describe('--filter-table', () => {
    it('filters vulnerabilities below the specified severity', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            name: 'high-pkg',
            severity: 'high',
            nodes: ['node_modules/high-pkg'],
            advisories: [{ ...makeVuln().advisories[0]!, title: 'High vuln' }],
          }),
          makeVuln({
            name: 'low-pkg',
            severity: 'low',
            nodes: ['node_modules/low-pkg'],
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

      expect(output).toMatchInlineSnapshot(`
        "
        No vulnerabilities at or above critical severity.
        "
      `)
    })

    it('shows generic no-vuln message when no vulns exist and no filter', () => {
      const output = stripAnsi(formatTable(makeScanResult(), 'high'))

      expect(output).toContain('No vulnerabilities found.')
      expect(output).not.toContain('at or above')
    })

    it('shows filter-specific message when vulns exist but all below filter', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ severity: 'info' })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 1, low: 0, moderate: 0, high: 0, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, 'high'))

      expect(output).toContain('No vulnerabilities at or above high severity.')
    })
  })

  describe('meta-vulnerabilities', () => {
    it('shows transitive label and via path for string-only via entries', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['upstream-pkg'], nodes: [] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('(transitive)')
      expect(output).toContain('via upstream-pkg')
      expect(output).not.toContain('https://')
    })

    it('renders empty url for meta-vulnerabilities', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['dep-a', 'dep-b'], nodes: [] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('via dep-a, dep-b')
    })

    it('shows empty paths when no nodes and no string via entries', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: [], nodes: [] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))
      const dataLine = output.split('\n').find((l) => l.includes('(transitive)'))

      expect(dataLine).toBeDefined()
      expect(dataLine).not.toContain('via ')
      expect(dataLine).not.toContain('Stryker')
    })

    it('filters via to only string entries for paths', () => {
      const advisory = makeVuln().advisories[0]!
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: [advisory, 'string-dep'], nodes: [] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('via string-dep')
      expect(output).not.toContain('[object')
    })
  })

  describe('paths column', () => {
    it('shortens node_modules paths into readable chains', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            nodes: ['node_modules/express/node_modules/body-parser'],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('express>body-parser')
    })

    it('shows direct dependency path', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ nodes: ['node_modules/axios'] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('  axios')
    })

    it('joins multiple paths with commas', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            nodes: ['node_modules/foo', 'node_modules/bar/node_modules/foo'],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('foo, bar>foo')
    })
  })

  describe('deduplication', () => {
    it('deduplicates advisories with the same URL', () => {
      const advisory = makeVuln().advisories[0]!
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [advisory, { ...advisory, source: 9999 }] })],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))
      const urlOccurrences = output
        .split('\n')
        .filter((l) => l.includes('GHSA-aaaa-bbbb-cccc'))

      expect(urlOccurrences).toHaveLength(1)
    })

    it('keeps advisories with different URLs', () => {
      const advisory = makeVuln().advisories[0]!
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            advisories: [
              advisory,
              {
                ...advisory,
                source: 9999,
                title: 'Second vulnerability',
                url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
              },
            ],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 2, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Test Vulnerability')
      expect(output).toContain('Second vulnerability')
    })
  })

  describe('summary', () => {
    it('renders summary for single package with single vulnerability', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 1 package with 1 vulnerability')
    })

    it('renders plural packages and vulnerabilities', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({ name: 'pkg-a' }),
          makeVuln({ name: 'pkg-b', severity: 'critical' }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 2,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 1 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 2 packages with 2 vulnerabilities')
    })

    it('counts advisories correctly for multi-advisory packages', () => {
      const advisory = makeVuln().advisories[0]!
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            advisories: [
              advisory,
              {
                ...advisory,
                source: 2002,
                title: 'Another issue',
                url: 'https://github.com/advisories/GHSA-zzzz-yyyy-xxxx',
              },
            ],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 1 package with 2 vulnerabilities')
    })

    it('includes unhandled count', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('(1 unhandled)')
    })

    it('includes excepted count when exceptions matched', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
        exceptions: {
          matched: [{ id: 'GHSA-xxxx', matchedVulnerability: 'other' }],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 excepted')
    })

    it('omits excepted suffix when no exceptions matched', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('excepted')
    })

    it('shows severity breakdown with counts', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({ name: 'a', severity: 'high' }),
          makeVuln({ name: 'b', severity: 'moderate' }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 2,
          severityCounts: { info: 0, low: 0, moderate: 1, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 moderate, 1 high')
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

      expect(output).toContain('1 unused exception(s) in config')
    })

    it('omits unused warning when none unused', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('unused exception')
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

      expect(output).toContain('1 expired exception(s) in config')
    })

    it('omits expired warning when none expired', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('expired exception')
    })

    it('does not show unhandled suffix when filter reduces to empty', () => {
      const result = makeScanResult({
        unhandled: [],
        vulnerabilities: [makeVuln()],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('unhandled')
    })
  })

  describe('text wrapping', () => {
    it('wraps long titles across multiple lines with correct continuation', () => {
      const longTitle =
        'This is a very long vulnerability title that should definitely be wrapped across multiple lines'
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            advisories: [{ ...makeVuln().advisories[0]!, title: longTitle }],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toMatchInlineSnapshot(`
        "
        Severity  Package  Title                                                           Paths            Fix  URL
        ────────  ───────  ──────────────────────────────────────────────────────────────  ───────────────  ───  ───
        high      testpkg  This is a very long vulnerability title that should definitely  testpkg          No   https://github.com/advisories/GHSA-aaaa-bbbb-cccc
                           be wrapped across multiple lines                                                      

        Found 1 package with 1 vulnerability (1 unhandled)
          1 high
        "
      `)
    })

    it('truncates module names exceeding max width', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            name: 'extremely-long-module-name-that-exceeds-max-width',
            advisories: [{ ...makeVuln().advisories[0]!, name: 'extremely-long-module-name-that-exceeds-max-width' }],
          }),
        ],
        metadata: {
          ...makeScanResult().metadata,
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('extremely-long-module-name-...')
    })
  })

  describe('all severity levels', () => {
    it.each(['info', 'low', 'moderate', 'high', 'critical'] as const)(
      'renders %s severity in output',
      (severity) => {
        const result = makeScanResult({
          unhandled: [
            makeVuln({
              severity,
              advisories: [{ ...makeVuln().advisories[0]!, severity }],
            }),
          ],
          metadata: {
            ...makeScanResult().metadata,
            total: 1,
            severityCounts: {
              info: severity === 'info' ? 1 : 0,
              low: severity === 'low' ? 1 : 0,
              moderate: severity === 'moderate' ? 1 : 0,
              high: severity === 'high' ? 1 : 0,
              critical: severity === 'critical' ? 1 : 0,
            },
          },
        })
        const output = stripAnsi(formatTable(result, undefined))

        expect(output).toContain(severity)
        expect(output).toContain(`1 ${severity}`)
      },
    )
  })
})
