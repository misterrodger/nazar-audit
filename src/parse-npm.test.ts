import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Result, type Vulnerability } from './types.js'
import { parseNpmAuditJson } from './parse-npm.js'

const fixtureDir = join(import.meta.dirname, 'fixtures')
const readFixture = (name: string): string => readFileSync(join(fixtureDir, name), 'utf-8')

const expectOkData = (
  result: Result<ReadonlyArray<Vulnerability>>,
): ReadonlyArray<Vulnerability> => {
  expect(result.ok).toBe(true)

  return (result as { ok: true; data: ReadonlyArray<Vulnerability> }).data
}

const expectErrMessage = (result: Result<ReadonlyArray<Vulnerability>>): string => {
  expect(result.ok).toBe(false)

  return (result as { ok: false; error: string }).error
}

describe('parseNpmAuditJson', () => {
  describe('fixture: real npm audit output', () => {
    it('parses real npm audit JSON successfully', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOkData(parseNpmAuditJson(json))

      expect(data.length).toBeGreaterThan(0)
    })

    it('extracts vulnerability names from real fixture', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOkData(parseNpmAuditJson(json))
      const names = data.map((v) => v.name)

      expect(names).toContain('brace-expansion')
    })

    it('parses advisory objects in via array', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOkData(parseNpmAuditJson(json))
      const withAdvisories = data.filter((v) => v.advisories.length > 0)

      expect(withAdvisories.length).toBeGreaterThan(0)

      const first = withAdvisories[0]!

      expect(first.advisories[0]).toMatchObject({
        source: expect.any(Number),
        title: expect.any(String),
        url: expect.stringContaining('github.com/advisories/GHSA-'),
        severity: expect.any(String),
        cwe: expect.any(Array),
      })
    })

    it('parses string references in via array', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOkData(parseNpmAuditJson(json))
      const withStringVia = data.filter((v) => v.via.some((entry) => typeof entry === 'string'))

      expect(withStringVia.length).toBeGreaterThan(0)
    })
  })

  describe('fixAvailable normalization', () => {
    const makeAuditJson = (fixAvailable: unknown): string =>
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          testpkg: {
            name: 'testpkg',
            severity: 'high',
            isDirect: false,
            via: [
              {
                source: 1,
                name: 'testpkg',
                dependency: 'testpkg',
                title: 'Test vulnerability',
                url: 'https://github.com/advisories/GHSA-test-test-test',
                severity: 'high',
                cwe: ['CWE-1'],
                cvss: { score: 7.5, vectorString: 'CVSS:3.1/AV:N' },
                range: '<1.0.0',
              },
            ],
            effects: [],
            range: '<1.0.0',
            nodes: ['node_modules/testpkg'],
            fixAvailable,
          },
        },
      } as const)

    it('normalizes fixAvailable false to kind none', () => {
      const data = expectOkData(parseNpmAuditJson(makeAuditJson(false)))

      expect(data[0]!.fixAvailable).toStrictEqual({ kind: 'none' })
    })

    it('normalizes fixAvailable true to kind compatible', () => {
      const data = expectOkData(parseNpmAuditJson(makeAuditJson(true)))

      expect(data[0]!.fixAvailable).toStrictEqual({ kind: 'compatible' })
    })

    it('normalizes fixAvailable object with isSemVerMajor true to kind breaking', () => {
      const data = expectOkData(
        parseNpmAuditJson(
          makeAuditJson({ name: 'parent', version: '2.0.0', isSemVerMajor: true } as const),
        ),
      )

      expect(data[0]!.fixAvailable).toStrictEqual({
        kind: 'breaking',
        name: 'parent',
        version: '2.0.0',
      })
    })

    it('normalizes fixAvailable object with isSemVerMajor false to kind compatible', () => {
      const data = expectOkData(
        parseNpmAuditJson(
          makeAuditJson({ name: 'parent', version: '1.2.3', isSemVerMajor: false } as const),
        ),
      )

      expect(data[0]!.fixAvailable).toStrictEqual({ kind: 'compatible' })
    })
  })

  describe('via polymorphism', () => {
    it('separates advisory objects and string references', () => {
      const json = JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          metapkg: {
            name: 'metapkg',
            severity: 'moderate',
            isDirect: true,
            via: ['otherpkg'],
            effects: [],
            range: '>=1.0.0',
            nodes: ['node_modules/metapkg'],
            fixAvailable: false,
          },
        },
      } as const)
      const data = expectOkData(parseNpmAuditJson(json))
      const vuln = data[0]!

      expect(vuln.via).toStrictEqual(['otherpkg'])
      expect(vuln.advisories).toStrictEqual([])
    })
  })

  describe('cvss vectorString null handling', () => {
    it('converts null vectorString to undefined', () => {
      const json = JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          testpkg: {
            name: 'testpkg',
            severity: 'moderate',
            isDirect: false,
            via: [
              {
                source: 42,
                name: 'testpkg',
                dependency: 'testpkg',
                title: 'Null vector test',
                url: 'https://github.com/advisories/GHSA-null-null-null',
                severity: 'moderate',
                cwe: [],
                cvss: { score: 0, vectorString: null },
                range: '<2.0.0',
              },
            ],
            effects: [],
            range: '<2.0.0',
            nodes: ['node_modules/testpkg'],
            fixAvailable: false,
          },
        },
      } as const)
      const data = expectOkData(parseNpmAuditJson(json))

      expect(data[0]!.advisories[0]!.cvss.vectorString).toBeUndefined()
    })
  })

  describe('error cases', () => {
    it('rejects invalid JSON', () => {
      expect(() => parseNpmAuditJson('not json')).toThrow()
    })

    it('rejects missing auditReportVersion', () => {
      const json = JSON.stringify({ vulnerabilities: {} } as const)
      const error = expectErrMessage(parseNpmAuditJson(json))

      expect(error).toContain('missing auditReportVersion')
    })

    it('rejects missing vulnerabilities field', () => {
      const json = JSON.stringify({ auditReportVersion: 2 } as const)
      const error = expectErrMessage(parseNpmAuditJson(json))

      expect(error).toContain('missing auditReportVersion or vulnerabilities')
    })

    it('rejects unsupported audit report version', () => {
      const json = JSON.stringify({ auditReportVersion: 1, vulnerabilities: {} } as const)
      const error = expectErrMessage(parseNpmAuditJson(json))

      expect(error).toContain('Unsupported audit report version')
    })

    it('returns empty array for zero vulnerabilities', () => {
      const json = JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} } as const)
      const data = expectOkData(parseNpmAuditJson(json))

      expect(data).toStrictEqual([])
    })
  })

  describe('severity mapping', () => {
    it.each(['info', 'low', 'moderate', 'high', 'critical'] as const)(
      'preserves %s severity',
      (severity) => {
        const json = JSON.stringify({
          auditReportVersion: 2,
          vulnerabilities: {
            pkg: {
              name: 'pkg',
              severity,
              isDirect: false,
              via: [],
              effects: [],
              range: '*',
              nodes: [],
              fixAvailable: false,
            },
          },
        } as const)
        const data = expectOkData(parseNpmAuditJson(json))

        expect(data[0]!.severity).toBe(severity)
      },
    )

    it('defaults unknown severity to info', () => {
      const json = JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          pkg: {
            name: 'pkg',
            severity: 'unknown-future-severity',
            isDirect: false,
            via: [],
            effects: [],
            range: '*',
            nodes: [],
            fixAvailable: false,
          },
        },
      } as const)
      const data = expectOkData(parseNpmAuditJson(json))

      expect(data[0]!.severity).toBe('info')
    })
  })
})
