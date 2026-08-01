import type { ExceptionEntry } from './types.js'
import { applyExceptions } from './exceptions.js'
import { makeVuln } from './test-helpers.js'

const FUTURE_DATE = '2099-12-31'
const PAST_DATE = '2020-01-01'
const NOW = new Date('2025-06-15')

describe('applyExceptions', () => {
  describe('matching by GHSA ID', () => {
    it('matches exception id against advisory URL', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-aaaa-bbbb-cccc' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result).toMatchInlineSnapshot(`
        {
          "expired": [],
          "matched": [
            {
              "id": "GHSA-aaaa-bbbb-cccc",
              "matchedVulnerability": "testpkg",
            },
          ],
          "unhandled": [],
          "unused": [],
        }
      `)
    })

    it('does not match partial GHSA ID prefix', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-aaaa' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
      expect(result.matched).toHaveLength(0)
    })

    it('does not match unrelated GHSA ID', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-xxxx-yyyy-zzzz' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
    })
  })

  describe('matching by numeric source', () => {
    it('matches exception id against advisory source number', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: '1001' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })

    it('does not match unrelated numeric source', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: '9999' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
    })
  })

  describe('matching by module name', () => {
    it('matches exception module against vulnerability name', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ module: 'testpkg' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })

    it('matches one module exception against multiple vulnerabilities', () => {
      const vulns = [makeVuln({ name: 'lodash' }), makeVuln({ name: 'lodash' })] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ module: 'lodash' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(2)
      expect(result.unused).toHaveLength(0)
    })

    it('does not match unrelated module name', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ module: 'other-pkg' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
    })
  })

  describe('expiry handling', () => {
    it('does not apply expired exceptions', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', expiry: PAST_DATE },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.expired).toHaveLength(1)
      expect(result.matched).toHaveLength(0)
    })

    it('applies non-expired exceptions', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', expiry: FUTURE_DATE },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.expired).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })

    it('treats unparseable expiry as not expired', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', expiry: 'not-a-date' },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
      expect(result.expired).toHaveLength(0)
    })

    it('treats exception expiring today as expired', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', expiry: '2025-06-15' },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.expired).toHaveLength(1)
      expect(result.unhandled).toHaveLength(1)
    })

    it('does not expire exceptions without expiry field', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-aaaa-bbbb-cccc' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.expired).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })
  })

  describe('active flag', () => {
    it('does not apply inactive exceptions', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', active: false },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.matched).toHaveLength(0)
    })

    it('applies exceptions with active defaulting to true', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-aaaa-bbbb-cccc' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })

    it('applies exceptions with active explicitly true', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc', active: true },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.matched).toHaveLength(1)
    })
  })

  describe('unused exception detection', () => {
    it('reports exceptions that match no vulnerabilities as unused', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc' },
        { id: 'GHSA-does-not-exist' },
        { module: 'nonexistent-pkg' },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unused).toMatchInlineSnapshot(`
        [
          {
            "id": "GHSA-does-not-exist",
          },
          {
            "module": "nonexistent-pkg",
          },
        ]
      `)
    })

    it('does not report inactive exceptions as unused', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-does-not-exist', active: false },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unused).toHaveLength(0)
    })

    it('does not report expired exceptions as unused', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-does-not-exist', expiry: PAST_DATE },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unused).toHaveLength(0)
    })
  })

  describe('edge cases', () => {
    it('returns all vulnerabilities as unhandled when no exceptions', () => {
      const vulns = [makeVuln(), makeVuln({ name: 'other' })] as const
      const result = applyExceptions(vulns, [], NOW)

      expect(result.unhandled).toHaveLength(2)
      expect(result.matched).toHaveLength(0)
      expect(result.unused).toHaveLength(0)
      expect(result.expired).toHaveLength(0)
    })

    it('returns all exceptions as unused when no vulnerabilities', () => {
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-aaaa-bbbb-cccc' },
        { module: 'testpkg' },
      ]
      const result = applyExceptions([], exceptions, NOW)

      expect(result.unhandled).toHaveLength(0)
      expect(result.unused).toHaveLength(2)
    })

    it('returns empty results for empty inputs', () => {
      const result = applyExceptions([], [], NOW)

      expect(result).toMatchInlineSnapshot(`
        {
          "expired": [],
          "matched": [],
          "unhandled": [],
          "unused": [],
        }
      `)
    })

    it('handles exception with neither id nor module as unused', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ notes: 'orphaned exception' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unused).toHaveLength(1)
      expect(result.unhandled).toHaveLength(1)
    })

    it('matches exception with both id and module via either field', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        { id: 'GHSA-wrong-wrong-wrong', module: 'testpkg' },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.matched).toHaveLength(1)
      expect(result.unhandled).toHaveLength(0)
    })

    it('preserves exception metadata in matched entries', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [
        {
          id: 'GHSA-aaaa-bbbb-cccc',
          notes: 'Not exploitable in our usage',
          addedBy: 'jrodger',
          expiry: FUTURE_DATE,
        },
      ]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.matched[0]).toMatchInlineSnapshot(`
        {
          "addedBy": "jrodger",
          "expiry": "2099-12-31",
          "id": "GHSA-aaaa-bbbb-cccc",
          "matchedVulnerability": "testpkg",
          "notes": "Not exploitable in our usage",
        }
      `)
    })

    it('maps unhandled vulnerabilities with correct structure', () => {
      const vulns = [makeVuln()] as const
      const result = applyExceptions(vulns, [], NOW)

      expect(result.unhandled[0]?.name).toBe('testpkg')
      expect(result.unhandled[0]?.severity).toBe('high')
    })

    it('matches by id when vuln has multiple advisories with mixed match', () => {
      const vulns = [
        makeVuln({
          advisories: [
            {
              ...makeVuln().advisories[0]!,
              source: 1001,
              url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
            },
            {
              ...makeVuln().advisories[0]!,
              source: 2002,
              url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
            },
          ],
        }),
      ] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-aaaa-bbbb-cccc' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.matched).toHaveLength(1)
      expect(result.unhandled).toHaveLength(0)
    })

    it('does not match when exception module is undefined', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-wrong', module: undefined }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
    })

    it('does not match when exception id is undefined', () => {
      const vulns = [makeVuln()] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: undefined, module: 'wrong-pkg' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.unhandled).toHaveLength(1)
      expect(result.unused).toHaveLength(1)
    })

    it('matches by URL id when URL has no slash', () => {
      const vulns = [
        makeVuln({
          advisories: [
            {
              ...makeVuln().advisories[0]!,
              url: 'GHSA-no-slash',
            },
          ],
        }),
      ] as const
      const exceptions: ReadonlyArray<ExceptionEntry> = [{ id: 'GHSA-no-slash' }]
      const result = applyExceptions(vulns, exceptions, NOW)

      expect(result.matched).toHaveLength(1)
    })
  })
})
