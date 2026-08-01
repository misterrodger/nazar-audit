import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parseNpmAuditJson } from './parse-npm.js'
import { expectOk, expectErr } from './test-helpers.js'

const fixtureDir = join(import.meta.dirname, 'fixtures')
const readFixture = (name: string): string => readFileSync(join(fixtureDir, name), 'utf-8')

const makeAuditJson = (overrides: Record<string, unknown> = {}): string =>
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
        fixAvailable: false,
        ...overrides,
      },
    },
  } as const)

describe('parseNpmAuditJson', () => {
  describe('fixture: real npm audit output', () => {
    it('parses real npm audit JSON successfully', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOk(parseNpmAuditJson(json))

      expect(data.length).toBeGreaterThan(0)
    })

    it('extracts vulnerability names from real fixture', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOk(parseNpmAuditJson(json))
      const names = data.map((v) => v.name)

      expect(names).toContain('brace-expansion')
    })

    it('parses advisory objects in via array', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOk(parseNpmAuditJson(json))
      const withAdvisories = data.filter((v) => v.advisories.length > 0)

      expect(withAdvisories.length).toBeGreaterThan(0)

      const first = withAdvisories[0]!

      expect(first.advisories[0]).toMatchInlineSnapshot(`
        {
          "cvss": {
            "score": 0,
            "vectorString": undefined,
          },
          "cwe": [
            "CWE-400",
            "CWE-1333",
          ],
          "dependency": "ajv",
          "name": "ajv",
          "range": "<6.14.0",
          "severity": "moderate",
          "source": 1113714,
          "title": "ajv has ReDoS when using \`$data\` option",
          "url": "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
        }
      `)
    })

    it('parses string references in via array', () => {
      const json = readFixture('npm-audit-real.json')
      const data = expectOk(parseNpmAuditJson(json))
      const withStringVia = data.filter((v) => v.via.some((entry) => typeof entry === 'string'))

      expect(withStringVia.length).toBeGreaterThan(0)
    })
  })

  describe('fixAvailable normalization', () => {
    it('normalizes fixAvailable false to kind none', () => {
      const data = expectOk(parseNpmAuditJson(makeAuditJson({ fixAvailable: false })))

      expect(data[0]!.fixAvailable).toMatchInlineSnapshot(`
        {
          "kind": "none",
        }
      `)
    })

    it('normalizes fixAvailable true to kind compatible', () => {
      const data = expectOk(parseNpmAuditJson(makeAuditJson({ fixAvailable: true })))

      expect(data[0]!.fixAvailable).toMatchInlineSnapshot(`
        {
          "kind": "compatible",
        }
      `)
    })

    it('normalizes fixAvailable object with isSemVerMajor true to kind breaking', () => {
      const data = expectOk(
        parseNpmAuditJson(
          makeAuditJson({
            fixAvailable: { name: 'parent', version: '2.0.0', isSemVerMajor: true },
          }),
        ),
      )

      expect(data[0]!.fixAvailable).toMatchInlineSnapshot(`
        {
          "kind": "breaking",
          "name": "parent",
          "version": "2.0.0",
        }
      `)
    })

    it('normalizes fixAvailable object with isSemVerMajor false to kind compatible', () => {
      const data = expectOk(
        parseNpmAuditJson(
          makeAuditJson({
            fixAvailable: { name: 'parent', version: '1.2.3', isSemVerMajor: false },
          }),
        ),
      )

      expect(data[0]!.fixAvailable).toMatchInlineSnapshot(`
        {
          "kind": "compatible",
        }
      `)
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
      const data = expectOk(parseNpmAuditJson(json))
      const vuln = data[0]!

      expect(vuln.via).toStrictEqual(['otherpkg'])
      expect(vuln.advisories).toStrictEqual([])
    })

    it('filters out invalid via entries', () => {
      const json = JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          testpkg: {
            name: 'testpkg',
            severity: 'high',
            isDirect: false,
            via: [42, { invalid: true }, 'valid-string'],
            effects: [],
            range: '*',
            nodes: [],
            fixAvailable: false,
          },
        },
      })
      const data = expectOk(parseNpmAuditJson(json))

      expect(data[0]!.via).toStrictEqual(['valid-string'])
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
      const data = expectOk(parseNpmAuditJson(json))

      expect(data[0]!.advisories[0]!.cvss).toMatchInlineSnapshot(`
        {
          "score": 0,
          "vectorString": undefined,
        }
      `)
    })

    it('preserves present vectorString', () => {
      const data = expectOk(parseNpmAuditJson(makeAuditJson()))

      expect(data[0]!.advisories[0]!.cvss).toMatchInlineSnapshot(`
        {
          "score": 7.5,
          "vectorString": "CVSS:3.1/AV:N",
        }
      `)
    })
  })

  describe('error cases', () => {
    it('returns err for invalid JSON', () => {
      const error = expectErr(parseNpmAuditJson('not json'))

      expect(error).toMatchInlineSnapshot(
        `"Failed to parse JSON: Unexpected token 'o', "not json" is not valid JSON"`,
      )
    })

    it('rejects missing auditReportVersion', () => {
      const json = JSON.stringify({ vulnerabilities: {} } as const)
      const error = expectErr(parseNpmAuditJson(json))

      expect(error).toMatchInlineSnapshot(
        `"Invalid npm audit output: Invalid key: Expected "auditReportVersion" but received undefined"`,
      )
    })

    it('rejects missing vulnerabilities field', () => {
      const json = JSON.stringify({ auditReportVersion: 2 } as const)
      const error = expectErr(parseNpmAuditJson(json))

      expect(error).toMatchInlineSnapshot(
        `"Invalid npm audit output: Invalid key: Expected "vulnerabilities" but received undefined"`,
      )
    })

    it('rejects unsupported audit report version', () => {
      const json = JSON.stringify({ auditReportVersion: 1, vulnerabilities: {} } as const)
      const error = expectErr(parseNpmAuditJson(json))

      expect(error).toMatchInlineSnapshot(
        `"Unsupported audit report version: 1. Only version 2 (npm v7+) is supported."`,
      )
    })

    it('joins multiple validation errors with comma separator', () => {
      const json = JSON.stringify({ notAuditReport: true })
      const error = expectErr(parseNpmAuditJson(json))

      expect(error).toContain(', ')
    })

    it('returns empty array for zero vulnerabilities', () => {
      const json = JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} } as const)
      const data = expectOk(parseNpmAuditJson(json))

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
        const data = expectOk(parseNpmAuditJson(json))

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
      const data = expectOk(parseNpmAuditJson(json))

      expect(data[0]!.severity).toBe('info')
    })
  })

  describe('full parsed structure', () => {
    it('parses a complete vulnerability with all fields', () => {
      const data = expectOk(parseNpmAuditJson(makeAuditJson()))

      expect(data[0]).toMatchInlineSnapshot(`
        {
          "advisories": [
            {
              "cvss": {
                "score": 7.5,
                "vectorString": "CVSS:3.1/AV:N",
              },
              "cwe": [
                "CWE-1",
              ],
              "dependency": "testpkg",
              "name": "testpkg",
              "range": "<1.0.0",
              "severity": "high",
              "source": 1,
              "title": "Test vulnerability",
              "url": "https://github.com/advisories/GHSA-test-test-test",
            },
          ],
          "effects": [],
          "fixAvailable": {
            "kind": "none",
          },
          "isDirect": false,
          "name": "testpkg",
          "nodes": [
            "node_modules/testpkg",
          ],
          "range": "<1.0.0",
          "severity": "high",
          "via": [
            {
              "cvss": {
                "score": 7.5,
                "vectorString": "CVSS:3.1/AV:N",
              },
              "cwe": [
                "CWE-1",
              ],
              "dependency": "testpkg",
              "name": "testpkg",
              "range": "<1.0.0",
              "severity": "high",
              "source": 1,
              "title": "Test vulnerability",
              "url": "https://github.com/advisories/GHSA-test-test-test",
            },
          ],
        }
      `)
    })
  })
})
