import { formatTable } from './report-table.js'
import { makeVuln, makeScanResult, makeAdvisory, makeMetadata } from './test-helpers.js'

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
      metadata: makeMetadata({
        total: 1,
        severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
      }),
    })
    const output = stripAnsi(formatTable(result, undefined))

    expect(output).toMatchInlineSnapshot(`
      "
      ID    Severity  Package  Title                 Paths            Fix  URL
      ────  ────────  ───────  ────────────────────  ───────────────  ───  ───
      1001  high      testpkg  Test Vulnerability    testpkg          No   https://github.com/advisories/GHSA-aaaa-bbbb-cccc

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
            makeAdvisory({
              severity: 'low',
              title: 'Low vuln',
              url: 'https://github.com/advisories/GHSA-low0-low0-low0',
            }),
          ],
        }),
        makeVuln({
          name: 'crit-pkg',
          severity: 'critical',
          nodes: ['node_modules/crit-pkg'],
          advisories: [
            makeAdvisory({
              severity: 'critical',
              title: 'Critical vuln',
              url: 'https://github.com/advisories/GHSA-crit-crit-crit',
            }),
          ],
        }),
      ],
      metadata: makeMetadata({
        total: 2,
        severityCounts: { info: 0, low: 1, moderate: 0, high: 0, critical: 1 },
      }),
    })
    const output = stripAnsi(formatTable(result, undefined))

    expect(output).toMatchInlineSnapshot(`
      "
      ID    Severity  Package   Title                 Paths            Fix  URL
      ────  ────────  ────────  ────────────────────  ───────────────  ───  ───
      1001  critical  crit-pkg  Critical vuln         crit-pkg         No   https://github.com/advisories/GHSA-crit-crit-crit
      1001  low       low-pkg   Low vuln              low-pkg          No   https://github.com/advisories/GHSA-low0-low0-low0

      Found 2 packages with 2 vulnerabilities (2 unhandled)
        1 low, 1 critical
      "
    `)
  })

  describe('fix availability display', () => {
    it('shows Yes for compatible fix', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ fixAvailable: { kind: 'compatible' } })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Breaking (parent@2.0.0)')
    })

    it('shows No when no fix available', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ fixAvailable: { kind: 'none' } })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
            advisories: [makeAdvisory({ title: 'High vuln' })],
          }),
          makeVuln({
            name: 'low-pkg',
            severity: 'low',
            nodes: ['node_modules/low-pkg'],
            advisories: [makeAdvisory({ severity: 'low', title: 'Low vuln' })],
          }),
        ],
        metadata: makeMetadata({
          total: 2,
          severityCounts: { info: 0, low: 1, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, 'high'))

      expect(output).toContain('High vuln')
      expect(output).not.toContain('Low vuln')
    })

    it('shows filter-aware message when filter excludes all', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ severity: 'low' })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 1, moderate: 0, high: 0, critical: 0 },
        }),
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
        unhandled: [
          makeVuln({
            severity: 'info',
            advisories: [makeAdvisory({ severity: 'info' })],
          }),
        ],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 1, low: 0, moderate: 0, high: 0, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, 'high'))

      expect(output).toContain('No vulnerabilities at or above high severity.')
    })
  })

  describe('meta-vulnerabilities', () => {
    it('shows transitive label and via path for string-only via entries', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['upstream-pkg'], nodes: [] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))
      const dataLine = output
        .split('\n')
        .find((line) => line.includes('(transitive via upstream-pkg)'))

      expect(dataLine).toMatch(/\(transitive via upstream-pkg\) +via upstream-pkg/)
      expect(dataLine).not.toContain('https://')
    })

    it('renders empty url for meta-vulnerabilities', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['dep-a', 'dep-b'], nodes: [] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('via dep-a, dep-b')
    })

    it('shows empty paths when no nodes and no string via entries', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: [], nodes: [] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))
      const dataLine = output.split('\n').find((line) => line.includes('(transitive)'))

      expect(dataLine).toBeDefined()
      expect(dataLine).not.toContain('via ')
      expect(dataLine).not.toContain('Stryker')
    })

    it('filters via to only string entries for paths', () => {
      const advisory = makeAdvisory()
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: [advisory, 'string-dep'], nodes: [] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('via string-dep')
      expect(output).not.toContain('[object')
    })
  })

  describe('id column', () => {
    it('renders a placeholder when the vulnerability has no advisory', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [], via: ['upstream-pkg'], nodes: [] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))
      const dataLine = output
        .split('\n')
        .find((line) => line.includes('(transitive via upstream-pkg)'))

      expect(dataLine).toMatch(/^- +high/)
    })

    it('renders the source id of each advisory on its own row', () => {
      const advisory = makeAdvisory()
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 2, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))
      const dataLines = output.split('\n')

      expect(dataLines.find((line) => line.includes('Test Vulnerability'))).toMatch(/^1001 +high/)
      expect(dataLines.find((line) => line.includes('Another issue'))).toMatch(/^2002 +high/)
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('express->body-parser')
    })

    it('preserves scoped package names in shortened paths', () => {
      const result = makeScanResult({
        unhandled: [
          makeVuln({
            nodes: ['node_modules/@scope/pkg/node_modules/dep'],
          }),
        ],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('@scope/pkg->dep')
    })

    it('shows direct dependency path', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ nodes: ['node_modules/axios'] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('foo, bar->foo')
    })
  })

  describe('deduplication', () => {
    it('deduplicates advisories with the same URL', () => {
      const advisory = makeAdvisory()
      const result = makeScanResult({
        unhandled: [makeVuln({ advisories: [advisory, { ...advisory, source: 9999 }] })],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))
      const urlOccurrences = output.split('\n').filter((l) => l.includes('GHSA-aaaa-bbbb-cccc'))

      expect(urlOccurrences).toHaveLength(1)
    })

    it('keeps advisories with different URLs', () => {
      const advisory = makeAdvisory()
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 2, critical: 0 },
        }),
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 1 package with 1 vulnerability')
    })

    it('renders plural packages and vulnerabilities', () => {
      const result = makeScanResult({
        unhandled: [makeVuln({ name: 'pkg-a' }), makeVuln({ name: 'pkg-b', severity: 'critical' })],
        metadata: makeMetadata({
          total: 2,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 1 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 2 packages with 2 vulnerabilities')
    })

    it('counts advisories correctly for multi-advisory packages', () => {
      const advisory = makeAdvisory()
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Found 1 package with 2 vulnerabilities')
    })

    it('includes unhandled count', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('(1 unhandled)')
    })

    it('includes excepted count when exceptions matched', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
        exceptions: {
          matched: [{ id: 'GHSA-xxxx', matchedVulnerability: 'other' }],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 excepted')
      expect(output).toContain('Exceptions were added for IDs GHSA-xxxx.')
    })

    it('lists unique ids for matched exceptions', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        exceptions: {
          matched: [
            { id: '123', matchedVulnerability: 'lodash' },
            { id: '456', matchedVulnerability: 'minimist' },
            { id: '123', matchedVulnerability: 'express' },
          ],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Exceptions were added for IDs 123, 456.')
    })

    it('lists unique packages for matched exceptions', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        exceptions: {
          matched: [
            { module: 'lodash', matchedVulnerability: 'lodash' },
            { module: 'minimist', matchedVulnerability: 'minimist' },
            { module: 'lodash', matchedVulnerability: 'express' },
          ],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('Exceptions were added for packages lodash, minimist.')
    })

    it('labels ids and packages for matched exceptions', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        exceptions: {
          matched: [
            { id: '123', module: 'lodash', matchedVulnerability: 'lodash' },
            { id: '456', module: 'minimist', matchedVulnerability: 'minimist' },
          ],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain(
        'Exceptions were added for IDs 123, 456 and packages lodash, minimist.',
      )
    })

    it('separates the matched exception sentence from the severity breakdown with a blank line', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
        exceptions: {
          matched: [{ id: '123', matchedVulnerability: 'other' }],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 high\n\nExceptions were added for IDs 123.')
    })

    it('lists matched exception ids when all vulnerabilities are excepted', () => {
      const result = makeScanResult({
        exceptions: {
          matched: [{ id: '123', matchedVulnerability: 'testpkg' }],
          unused: [],
          expired: [],
        },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('No vulnerabilities found.\n\nExceptions were added for IDs 123.')
    })

    it('omits excepted suffix when no exceptions matched', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
        metadata: makeMetadata({
          total: 2,
          severityCounts: { info: 0, low: 0, moderate: 1, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 moderate, 1 high')
    })

    it('shows unused exception warning', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
        exceptions: { matched: [], unused: [{ id: 'GHSA-orphan' }], expired: [] },
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).toContain('1 unused exception(s) in config')
    })

    it('omits unused warning when none unused', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('unused exception')
    })

    it('shows expired exception warning', () => {
      const result = makeScanResult({
        unhandled: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined))

      expect(output).not.toContain('expired exception')
    })

    it('does not show unhandled suffix when filter reduces to empty', () => {
      const result = makeScanResult({
        unhandled: [],
        vulnerabilities: [makeVuln()],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
            advisories: [makeAdvisory({ title: longTitle })],
          }),
        ],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
      })
      const output = stripAnsi(formatTable(result, undefined)).replace(/[ \t]+$/gm, '')

      expect(output).toMatchInlineSnapshot(`
        "
        ID    Severity  Package  Title                                                      Paths            Fix  URL
        ────  ────────  ───────  ─────────────────────────────────────────────────────────  ───────────────  ───  ───
        1001  high      testpkg  This is a very long vulnerability title that should        testpkg          No   https://github.com/advisories/GHSA-aaaa-bbbb-cccc
                                 definitely be wrapped across multiple lines

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
            advisories: [
              makeAdvisory({
                name: 'extremely-long-module-name-that-exceeds-max-width',
              }),
            ],
          }),
        ],
        metadata: makeMetadata({
          total: 1,
          severityCounts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        }),
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
              advisories: [makeAdvisory({ severity })],
            }),
          ],
          metadata: makeMetadata({
            total: 1,
            severityCounts: {
              info: severity === 'info' ? 1 : 0,
              low: severity === 'low' ? 1 : 0,
              moderate: severity === 'moderate' ? 1 : 0,
              high: severity === 'high' ? 1 : 0,
              critical: severity === 'critical' ? 1 : 0,
            },
          }),
        })
        const output = stripAnsi(formatTable(result, undefined))

        expect(output).toContain(severity)
        expect(output).toContain(`1 ${severity}`)
      },
    )
  })
})
