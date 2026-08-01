import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { vi } from 'vitest'
import { makeVuln, makeScanResult, expectOk, expectErr } from './test-helpers.js'

const mockState = { stdout: '', shouldError: false, stderrText: '' }

vi.mock('node:child_process', () => {
  const execFileMock = vi.fn()

  const promisified = () =>
    mockState.shouldError
      ? Promise.reject(
          Object.assign(new Error('npm audit found vulnerabilities'), {
            stdout: mockState.stdout,
            stderr: mockState.stderrText,
          }),
        )
      : Promise.resolve({ stdout: mockState.stdout, stderr: '' })

  // @ts-expect-error -- promisify reads this symbol to use our mock
  execFileMock[Symbol.for('nodejs.util.promisify.custom')] = promisified

  return { execFile: execFileMock }
})

const fixtureDir = join(import.meta.dirname, 'fixtures')
const readFixture = (name: string): string => readFileSync(join(fixtureDir, name), 'utf-8')

const setMockAudit = (stdout: string, shouldError = false, stderrText = ''): void => {
  mockState.stdout = stdout
  mockState.shouldError = shouldError
  mockState.stderrText = stderrText
}

describe('scan', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    setMockAudit('')
  })

  it('parses real npm audit fixture and returns ScanResult', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result).toMatchInlineSnapshot(`
      {
        "exceptions": {
          "expired": [],
          "matched": [],
          "unused": [],
        },
        "metadata": {
          "directCount": 1,
          "fixableCount": 9,
          "severityCounts": {
            "critical": 0,
            "high": 7,
            "info": 0,
            "low": 0,
            "moderate": 2,
          },
          "total": 9,
          "transitiveCount": 8,
          "unfixableCount": 0,
        },
        "packageManager": "npm",
        "unhandled": [
          {
            "advisories": [
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
              },
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
                "range": ">=7.0.0-alpha.0 <8.18.0",
                "severity": "moderate",
                "source": 1113715,
                "title": "ajv has ReDoS when using \`$data\` option",
                "url": "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "ajv",
            "nodes": [
              "node_modules/ajv",
              "node_modules/table/node_modules/ajv",
            ],
            "range": "<6.14.0 || >=7.0.0-alpha.0 <8.18.0",
            "severity": "moderate",
            "via": [
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
              },
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
                "range": ">=7.0.0-alpha.0 <8.18.0",
                "severity": "moderate",
                "source": 1113715,
                "title": "ajv has ReDoS when using \`$data\` option",
                "url": "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.13",
                "severity": "moderate",
                "source": 1115540,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.0.3",
                "severity": "moderate",
                "source": 1115541,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.2",
                "severity": "high",
                "source": 1123896,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.16",
                "severity": "high",
                "source": 1123897,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.17",
                "severity": "high",
                "source": 1130588,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.3",
                "severity": "high",
                "source": 1130589,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "brace-expansion",
            "nodes": [
              "node_modules/brace-expansion",
              "node_modules/glob/node_modules/brace-expansion",
              "node_modules/mocha/node_modules/brace-expansion",
            ],
            "range": "<=1.1.16 || 2.0.0 - 2.1.2",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.13",
                "severity": "moderate",
                "source": 1115540,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.0.3",
                "severity": "moderate",
                "source": 1115541,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.2",
                "severity": "high",
                "source": 1123896,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.16",
                "severity": "high",
                "source": 1123897,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.17",
                "severity": "high",
                "source": 1130588,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.3",
                "severity": "high",
                "source": 1130589,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-22",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.0",
                "severity": "high",
                "source": 1117870,
                "title": "fast-uri vulnerable to path traversal via percent-encoded dot segments",
                "url": "https://github.com/advisories/GHSA-q3j6-qgpj-74h6",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.1",
                "severity": "high",
                "source": 1117884,
                "title": "fast-uri vulnerable to host confusion via percent-encoded authority delimiters",
                "url": "https://github.com/advisories/GHSA-v39h-62p7-jpjc",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <=3.1.3",
                "severity": "high",
                "source": 1124064,
                "title": "fast-uri vulnerable to host confusion via literal backslash authority delimiter",
                "url": "https://github.com/advisories/GHSA-v2hh-gcrm-f6hx",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                  "CWE-551",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <3.1.3",
                "severity": "high",
                "source": 1130178,
                "title": "fast-uri vulnerable to host confusion via failed IDN canonicalization",
                "url": "https://github.com/advisories/GHSA-4c8g-83qw-93j6",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "fast-uri",
            "nodes": [
              "node_modules/fast-uri",
            ],
            "range": "<=3.1.3",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-22",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.0",
                "severity": "high",
                "source": 1117870,
                "title": "fast-uri vulnerable to path traversal via percent-encoded dot segments",
                "url": "https://github.com/advisories/GHSA-q3j6-qgpj-74h6",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.1",
                "severity": "high",
                "source": 1117884,
                "title": "fast-uri vulnerable to host confusion via percent-encoded authority delimiters",
                "url": "https://github.com/advisories/GHSA-v39h-62p7-jpjc",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <=3.1.3",
                "severity": "high",
                "source": 1124064,
                "title": "fast-uri vulnerable to host confusion via literal backslash authority delimiter",
                "url": "https://github.com/advisories/GHSA-v2hh-gcrm-f6hx",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                  "CWE-551",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <3.1.3",
                "severity": "high",
                "source": 1130178,
                "title": "fast-uri vulnerable to host confusion via failed IDN canonicalization",
                "url": "https://github.com/advisories/GHSA-4c8g-83qw-93j6",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-674",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<3.4.0",
                "severity": "high",
                "source": 1114526,
                "title": "flatted vulnerable to unbounded recursion DoS in parse() revive phase",
                "url": "https://github.com/advisories/GHSA-25h7-pfq9-p65f",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<=3.4.1",
                "severity": "high",
                "source": 1115357,
                "title": "Prototype Pollution via parse() in NodeJS flatted",
                "url": "https://github.com/advisories/GHSA-rf6f-7fwh-wjgh",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "flatted",
            "nodes": [
              "node_modules/flatted",
            ],
            "range": "<=3.4.1",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-674",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<3.4.0",
                "severity": "high",
                "source": 1114526,
                "title": "flatted vulnerable to unbounded recursion DoS in parse() revive phase",
                "url": "https://github.com/advisories/GHSA-25h7-pfq9-p65f",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<=3.4.1",
                "severity": "high",
                "source": 1115357,
                "title": "Prototype Pollution via parse() in NodeJS flatted",
                "url": "https://github.com/advisories/GHSA-rf6f-7fwh-wjgh",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": "<3.15.0",
                "severity": "moderate",
                "source": 1121859,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <=4.1.1",
                "severity": "moderate",
                "source": 1121860,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <4.3.0",
                "severity": "high",
                "source": 1123911,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=3.0.0 <3.15.0",
                "severity": "high",
                "source": 1123912,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "js-yaml",
            "nodes": [
              "node_modules/js-yaml",
              "node_modules/mocha/node_modules/js-yaml",
            ],
            "range": "<=3.14.2 || 4.0.0 - 4.2.0",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": "<3.15.0",
                "severity": "moderate",
                "source": 1121859,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <=4.1.1",
                "severity": "moderate",
                "source": 1121860,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <4.3.0",
                "severity": "high",
                "source": 1123911,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=3.0.0 <3.15.0",
                "severity": "high",
                "source": 1123912,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113459,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.7",
                "severity": "high",
                "source": 1113461,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113538,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113540,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.4",
                "severity": "high",
                "source": 1113546,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113548,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "minimatch",
            "nodes": [
              "node_modules/glob/node_modules/minimatch",
              "node_modules/minimatch",
              "node_modules/mocha/node_modules/minimatch",
            ],
            "range": "<=3.1.3 || 5.0.0 - 5.1.7",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113459,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.7",
                "severity": "high",
                "source": 1113461,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113538,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113540,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.4",
                "severity": "high",
                "source": 1113546,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113548,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
            ],
          },
          {
            "advisories": [],
            "effects": [],
            "fixAvailable": {
              "kind": "breaking",
              "name": "mocha",
              "version": "8.1.3",
            },
            "isDirect": true,
            "name": "mocha",
            "nodes": [
              "node_modules/mocha",
            ],
            "range": "8.2.0 - 12.0.0-beta-2",
            "severity": "moderate",
            "via": [
              "serialize-javascript",
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "moderate",
                "source": 1115549,
                "title": "Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching",
                "url": "https://github.com/advisories/GHSA-3v7f-55p6-f55p",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "high",
                "source": 1115552,
                "title": "Picomatch has a ReDoS vulnerability via extglob quantifiers",
                "url": "https://github.com/advisories/GHSA-c2c7-rcm5-vvqj",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "picomatch",
            "nodes": [
              "node_modules/picomatch",
            ],
            "range": "<=2.3.1",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "moderate",
                "source": 1115549,
                "title": "Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching",
                "url": "https://github.com/advisories/GHSA-3v7f-55p6-f55p",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "high",
                "source": 1115552,
                "title": "Picomatch has a ReDoS vulnerability via extglob quantifiers",
                "url": "https://github.com/advisories/GHSA-c2c7-rcm5-vvqj",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 8.1,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "cwe": [
                  "CWE-96",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": "<=7.0.2",
                "severity": "high",
                "source": 1113686,
                "title": "Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()",
                "url": "https://github.com/advisories/GHSA-5c6j-r48x-rmvq",
              },
              {
                "cvss": {
                  "score": 5.9,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-834",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": ">=5.0.0 <7.0.5",
                "severity": "moderate",
                "source": 1119440,
                "title": "Serialize JavaScript has CPU Exhaustion Denial of Service via crafted array-like objects",
                "url": "https://github.com/advisories/GHSA-qj8w-gfj5-8c6v",
              },
            ],
            "effects": [
              "mocha",
            ],
            "fixAvailable": {
              "kind": "breaking",
              "name": "mocha",
              "version": "8.1.3",
            },
            "isDirect": false,
            "name": "serialize-javascript",
            "nodes": [
              "node_modules/serialize-javascript",
            ],
            "range": "<=7.0.4",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 8.1,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "cwe": [
                  "CWE-96",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": "<=7.0.2",
                "severity": "high",
                "source": 1113686,
                "title": "Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()",
                "url": "https://github.com/advisories/GHSA-5c6j-r48x-rmvq",
              },
              {
                "cvss": {
                  "score": 5.9,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-834",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": ">=5.0.0 <7.0.5",
                "severity": "moderate",
                "source": 1119440,
                "title": "Serialize JavaScript has CPU Exhaustion Denial of Service via crafted array-like objects",
                "url": "https://github.com/advisories/GHSA-qj8w-gfj5-8c6v",
              },
            ],
          },
        ],
        "vulnerabilities": [
          {
            "advisories": [
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
              },
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
                "range": ">=7.0.0-alpha.0 <8.18.0",
                "severity": "moderate",
                "source": 1113715,
                "title": "ajv has ReDoS when using \`$data\` option",
                "url": "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "ajv",
            "nodes": [
              "node_modules/ajv",
              "node_modules/table/node_modules/ajv",
            ],
            "range": "<6.14.0 || >=7.0.0-alpha.0 <8.18.0",
            "severity": "moderate",
            "via": [
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
              },
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
                "range": ">=7.0.0-alpha.0 <8.18.0",
                "severity": "moderate",
                "source": 1113715,
                "title": "ajv has ReDoS when using \`$data\` option",
                "url": "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.13",
                "severity": "moderate",
                "source": 1115540,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.0.3",
                "severity": "moderate",
                "source": 1115541,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.2",
                "severity": "high",
                "source": 1123896,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.16",
                "severity": "high",
                "source": 1123897,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.17",
                "severity": "high",
                "source": 1130588,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.3",
                "severity": "high",
                "source": 1130589,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "brace-expansion",
            "nodes": [
              "node_modules/brace-expansion",
              "node_modules/glob/node_modules/brace-expansion",
              "node_modules/mocha/node_modules/brace-expansion",
            ],
            "range": "<=1.1.16 || 2.0.0 - 2.1.2",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.13",
                "severity": "moderate",
                "source": 1115540,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 6.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.0.3",
                "severity": "moderate",
                "source": 1115541,
                "title": "brace-expansion: Zero-step sequence causes process hang and memory exhaustion",
                "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.2",
                "severity": "high",
                "source": 1123896,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.16",
                "severity": "high",
                "source": 1123897,
                "title": "brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups",
                "url": "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": "<1.1.17",
                "severity": "high",
                "source": 1130588,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-770",
                ],
                "dependency": "brace-expansion",
                "name": "brace-expansion",
                "range": ">=2.0.0 <2.1.3",
                "severity": "high",
                "source": 1130589,
                "title": "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
                "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-22",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.0",
                "severity": "high",
                "source": 1117870,
                "title": "fast-uri vulnerable to path traversal via percent-encoded dot segments",
                "url": "https://github.com/advisories/GHSA-q3j6-qgpj-74h6",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.1",
                "severity": "high",
                "source": 1117884,
                "title": "fast-uri vulnerable to host confusion via percent-encoded authority delimiters",
                "url": "https://github.com/advisories/GHSA-v39h-62p7-jpjc",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <=3.1.3",
                "severity": "high",
                "source": 1124064,
                "title": "fast-uri vulnerable to host confusion via literal backslash authority delimiter",
                "url": "https://github.com/advisories/GHSA-v2hh-gcrm-f6hx",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                  "CWE-551",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <3.1.3",
                "severity": "high",
                "source": 1130178,
                "title": "fast-uri vulnerable to host confusion via failed IDN canonicalization",
                "url": "https://github.com/advisories/GHSA-4c8g-83qw-93j6",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "fast-uri",
            "nodes": [
              "node_modules/fast-uri",
            ],
            "range": "<=3.1.3",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-22",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.0",
                "severity": "high",
                "source": 1117870,
                "title": "fast-uri vulnerable to path traversal via percent-encoded dot segments",
                "url": "https://github.com/advisories/GHSA-q3j6-qgpj-74h6",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": "<=3.1.1",
                "severity": "high",
                "source": 1117884,
                "title": "fast-uri vulnerable to host confusion via percent-encoded authority delimiters",
                "url": "https://github.com/advisories/GHSA-v39h-62p7-jpjc",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <=3.1.3",
                "severity": "high",
                "source": 1124064,
                "title": "fast-uri vulnerable to host confusion via literal backslash authority delimiter",
                "url": "https://github.com/advisories/GHSA-v2hh-gcrm-f6hx",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "cwe": [
                  "CWE-436",
                  "CWE-551",
                ],
                "dependency": "fast-uri",
                "name": "fast-uri",
                "range": ">=3.0.0 <3.1.3",
                "severity": "high",
                "source": 1130178,
                "title": "fast-uri vulnerable to host confusion via failed IDN canonicalization",
                "url": "https://github.com/advisories/GHSA-4c8g-83qw-93j6",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-674",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<3.4.0",
                "severity": "high",
                "source": 1114526,
                "title": "flatted vulnerable to unbounded recursion DoS in parse() revive phase",
                "url": "https://github.com/advisories/GHSA-25h7-pfq9-p65f",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<=3.4.1",
                "severity": "high",
                "source": 1115357,
                "title": "Prototype Pollution via parse() in NodeJS flatted",
                "url": "https://github.com/advisories/GHSA-rf6f-7fwh-wjgh",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "flatted",
            "nodes": [
              "node_modules/flatted",
            ],
            "range": "<=3.4.1",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-674",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<3.4.0",
                "severity": "high",
                "source": 1114526,
                "title": "flatted vulnerable to unbounded recursion DoS in parse() revive phase",
                "url": "https://github.com/advisories/GHSA-25h7-pfq9-p65f",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "flatted",
                "name": "flatted",
                "range": "<=3.4.1",
                "severity": "high",
                "source": 1115357,
                "title": "Prototype Pollution via parse() in NodeJS flatted",
                "url": "https://github.com/advisories/GHSA-rf6f-7fwh-wjgh",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": "<3.15.0",
                "severity": "moderate",
                "source": 1121859,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <=4.1.1",
                "severity": "moderate",
                "source": 1121860,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <4.3.0",
                "severity": "high",
                "source": 1123911,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=3.0.0 <3.15.0",
                "severity": "high",
                "source": 1123912,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "js-yaml",
            "nodes": [
              "node_modules/js-yaml",
              "node_modules/mocha/node_modules/js-yaml",
            ],
            "range": "<=3.14.2 || 4.0.0 - 4.2.0",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": "<3.15.0",
                "severity": "moderate",
                "source": 1121859,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <=4.1.1",
                "severity": "moderate",
                "source": 1121860,
                "title": "JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases",
                "url": "https://github.com/advisories/GHSA-h67p-54hq-rp68",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=4.0.0 <4.3.0",
                "severity": "high",
                "source": 1123911,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-407",
                ],
                "dependency": "js-yaml",
                "name": "js-yaml",
                "range": ">=3.0.0 <3.15.0",
                "severity": "high",
                "source": 1123912,
                "title": "js-yaml: YAML merge-key chains can force quadratic CPU consumption",
                "url": "https://github.com/advisories/GHSA-52cp-r559-cp3m",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113459,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.7",
                "severity": "high",
                "source": 1113461,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113538,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113540,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.4",
                "severity": "high",
                "source": 1113546,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113548,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "minimatch",
            "nodes": [
              "node_modules/glob/node_modules/minimatch",
              "node_modules/minimatch",
              "node_modules/mocha/node_modules/minimatch",
            ],
            "range": "<=3.1.3 || 5.0.0 - 5.1.7",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113459,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 0,
                  "vectorString": undefined,
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.7",
                "severity": "high",
                "source": 1113461,
                "title": "minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern",
                "url": "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.3",
                "severity": "high",
                "source": 1113538,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-407",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113540,
                "title": "minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments",
                "url": "https://github.com/advisories/GHSA-7r86-cg39-jmmj",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": "<3.1.4",
                "severity": "high",
                "source": 1113546,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "minimatch",
                "name": "minimatch",
                "range": ">=5.0.0 <5.1.8",
                "severity": "high",
                "source": 1113548,
                "title": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
                "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74",
              },
            ],
          },
          {
            "advisories": [],
            "effects": [],
            "fixAvailable": {
              "kind": "breaking",
              "name": "mocha",
              "version": "8.1.3",
            },
            "isDirect": true,
            "name": "mocha",
            "nodes": [
              "node_modules/mocha",
            ],
            "range": "8.2.0 - 12.0.0-beta-2",
            "severity": "moderate",
            "via": [
              "serialize-javascript",
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "moderate",
                "source": 1115549,
                "title": "Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching",
                "url": "https://github.com/advisories/GHSA-3v7f-55p6-f55p",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "high",
                "source": 1115552,
                "title": "Picomatch has a ReDoS vulnerability via extglob quantifiers",
                "url": "https://github.com/advisories/GHSA-c2c7-rcm5-vvqj",
              },
            ],
            "effects": [],
            "fixAvailable": {
              "kind": "compatible",
            },
            "isDirect": false,
            "name": "picomatch",
            "nodes": [
              "node_modules/picomatch",
            ],
            "range": "<=2.3.1",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 5.3,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                },
                "cwe": [
                  "CWE-1321",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "moderate",
                "source": 1115549,
                "title": "Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching",
                "url": "https://github.com/advisories/GHSA-3v7f-55p6-f55p",
              },
              {
                "cvss": {
                  "score": 7.5,
                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-1333",
                ],
                "dependency": "picomatch",
                "name": "picomatch",
                "range": "<2.3.2",
                "severity": "high",
                "source": 1115552,
                "title": "Picomatch has a ReDoS vulnerability via extglob quantifiers",
                "url": "https://github.com/advisories/GHSA-c2c7-rcm5-vvqj",
              },
            ],
          },
          {
            "advisories": [
              {
                "cvss": {
                  "score": 8.1,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "cwe": [
                  "CWE-96",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": "<=7.0.2",
                "severity": "high",
                "source": 1113686,
                "title": "Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()",
                "url": "https://github.com/advisories/GHSA-5c6j-r48x-rmvq",
              },
              {
                "cvss": {
                  "score": 5.9,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-834",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": ">=5.0.0 <7.0.5",
                "severity": "moderate",
                "source": 1119440,
                "title": "Serialize JavaScript has CPU Exhaustion Denial of Service via crafted array-like objects",
                "url": "https://github.com/advisories/GHSA-qj8w-gfj5-8c6v",
              },
            ],
            "effects": [
              "mocha",
            ],
            "fixAvailable": {
              "kind": "breaking",
              "name": "mocha",
              "version": "8.1.3",
            },
            "isDirect": false,
            "name": "serialize-javascript",
            "nodes": [
              "node_modules/serialize-javascript",
            ],
            "range": "<=7.0.4",
            "severity": "high",
            "via": [
              {
                "cvss": {
                  "score": 8.1,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "cwe": [
                  "CWE-96",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": "<=7.0.2",
                "severity": "high",
                "source": 1113686,
                "title": "Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()",
                "url": "https://github.com/advisories/GHSA-5c6j-r48x-rmvq",
              },
              {
                "cvss": {
                  "score": 5.9,
                  "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "cwe": [
                  "CWE-400",
                  "CWE-834",
                ],
                "dependency": "serialize-javascript",
                "name": "serialize-javascript",
                "range": ">=5.0.0 <7.0.5",
                "severity": "moderate",
                "source": 1119440,
                "title": "Serialize JavaScript has CPU Exhaustion Denial of Service via crafted array-like objects",
                "url": "https://github.com/advisories/GHSA-qj8w-gfj5-8c6v",
              },
            ],
          },
        ],
      }
    `)
  })

  it('applies CLI ignores to reduce unhandled count', async () => {
    const fixture = readFixture('npm-audit-real.json')
    const { scan } = await import('./scan.js')

    setMockAudit(fixture)
    const withoutIgnores = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    setMockAudit(fixture)
    const withIgnores = expectOk(
      await scan({
        cwd: '/tmp',
        production: false,
        cliIgnores: ['GHSA-2g4f-4pwh-qvx6'],
        configPath: undefined,
      }),
    )

    expect(withIgnores.unhandled.length).toBeLessThan(withoutIgnores.unhandled.length)
    expect(withIgnores.exceptions.matched.length).toBeGreaterThan(0)
  })

  it('returns err when npm audit produces no output', async () => {
    setMockAudit('')
    const { scan } = await import('./scan.js')

    const error = expectErr(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(error).toBe('npm audit produced no output')
  })

  it('returns err for invalid JSON from npm audit error', async () => {
    setMockAudit('not valid json', true)
    const { scan } = await import('./scan.js')

    const error = expectErr(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(error).toContain('Failed to parse JSON')
  })

  it('extracts stdout from npm audit exit code 1 errors', async () => {
    setMockAudit(readFixture('npm-audit-real.json'), true)
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result.vulnerabilities.length).toBeGreaterThan(0)
  })

  it('uses stderr for error message when available', async () => {
    setMockAudit('', true, 'Registry error: ENOTFOUND')
    const { scan } = await import('./scan.js')

    const error = expectErr(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(error).toBe('npm audit failed: Registry error: ENOTFOUND')
  })

  it('falls back to error.message when stderr is empty', async () => {
    setMockAudit('', true, '')
    const { scan } = await import('./scan.js')

    const error = expectErr(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(error).toBe('npm audit failed: npm audit found vulnerabilities')
  })

  it('returns err when config path does not exist', async () => {
    const { scan } = await import('./scan.js')

    const error = expectErr(
      await scan({
        cwd: '/tmp',
        production: false,
        cliIgnores: [],
        configPath: '/nonexistent/path/.nazar.yml',
      }),
    )

    expect(error).toContain('Config file not found')
  })

  it('populates severity counts correctly', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result.metadata.severityCounts).toMatchInlineSnapshot(`
      {
        "critical": 0,
        "high": 7,
        "info": 0,
        "low": 0,
        "moderate": 2,
      }
    `)

    const totalFromCounts = Object.values(result.metadata.severityCounts).reduce(
      (a, b) => a + b,
      0,
    )

    expect(totalFromCounts).toBe(result.metadata.total)
  })

  it('counts direct and transitive vulnerabilities', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result.metadata.directCount + result.metadata.transitiveCount).toBe(
      result.metadata.total,
    )
  })

  it('counts fixable and unfixable vulnerabilities with mixed fixture', async () => {
    const mixedFixture = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        fixable: {
          name: 'fixable-pkg',
          severity: 'high',
          isDirect: false,
          via: [],
          effects: [],
          range: '<1.0.0',
          nodes: ['node_modules/fixable-pkg'],
          fixAvailable: true,
        },
        unfixable: {
          name: 'unfixable-pkg',
          severity: 'moderate',
          isDirect: true,
          via: [],
          effects: [],
          range: '*',
          nodes: ['node_modules/unfixable-pkg'],
          fixAvailable: false,
        },
      },
    })
    setMockAudit(mixedFixture)
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result.metadata.fixableCount).toBe(1)
    expect(result.metadata.unfixableCount).toBe(1)
    expect(result.metadata.fixableCount + result.metadata.unfixableCount).toBe(
      result.metadata.total,
    )
  })
})

describe('passesThreshold', () => {
  it('passes when no unhandled vulnerabilities', async () => {
    const { passesThreshold } = await import('./scan.js')

    expect(passesThreshold(makeScanResult(), 'low')).toBe(true)
  })

  it('fails when unhandled vulnerability meets threshold', async () => {
    const { passesThreshold } = await import('./scan.js')
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'high' })],
    })

    expect(passesThreshold(result, 'high')).toBe(false)
  })

  it('passes when unhandled vulnerability is below threshold', async () => {
    const { passesThreshold } = await import('./scan.js')
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' })],
    })

    expect(passesThreshold(result, 'high')).toBe(true)
  })

  it('fails when any unhandled vulnerability meets threshold', async () => {
    const { passesThreshold } = await import('./scan.js')
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' }), makeVuln({ severity: 'critical' })],
    })

    expect(passesThreshold(result, 'high')).toBe(false)
  })

  it('defaults to low threshold when level is undefined', async () => {
    const { passesThreshold } = await import('./scan.js')
    const infoResult = makeScanResult({
      unhandled: [makeVuln({ severity: 'info' })],
    })
    const lowResult = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' })],
    })

    expect(passesThreshold(infoResult, undefined)).toBe(true)
    expect(passesThreshold(lowResult, undefined)).toBe(false)
  })

  it('passes info-level vulns when threshold is low', async () => {
    const { passesThreshold } = await import('./scan.js')
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'info' })],
    })

    expect(passesThreshold(result, 'low')).toBe(true)
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
    async ({ severity, level, expected }) => {
      const { passesThreshold } = await import('./scan.js')
      const result = makeScanResult({
        unhandled: [makeVuln({ severity })],
      })

      expect(passesThreshold(result, level)).toBe(expected)
    },
  )
})
