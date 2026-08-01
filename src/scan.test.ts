import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { vi } from 'vitest'
import { makeVuln, makeScanResult, expectOk, expectErr } from './test-helpers.js'

const mockState = { stdout: '', shouldError: false, stderrText: '' }
const mockCalls: ReadonlyArray<ReadonlyArray<unknown>>[] = []

vi.mock('node:child_process', () => {
  const execFileMock = vi.fn()

  const promisified = (...callArgs: ReadonlyArray<unknown>) => {
    mockCalls.push([callArgs])

    return mockState.shouldError
      ? Promise.reject(
          Object.assign(new Error('npm audit found vulnerabilities'), {
            stdout: mockState.stdout,
            stderr: mockState.stderrText,
          }),
        )
      : Promise.resolve({ stdout: mockState.stdout, stderr: '' })
  }

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
    mockCalls.length = 0
  })

  it('parses real npm audit fixture and returns ScanResult', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    const result = expectOk(
      await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }),
    )

    expect(result).toMatchSnapshot()
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

    const totalFromCounts = Object.values(result.metadata.severityCounts).reduce((a, b) => a + b, 0)

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

  it('passes --omit=dev args when production is true', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    expectOk(await scan({ cwd: '/tmp', production: true, cliIgnores: [], configPath: undefined }))

    const [lastCall] = mockCalls.slice(-1)
    const [callArgs] = lastCall ?? []

    expect(callArgs?.[1]).toStrictEqual(['audit', '--json', '--omit=dev'])
  })

  it('passes standard args when production is false', async () => {
    setMockAudit(readFixture('npm-audit-real.json'))
    const { scan } = await import('./scan.js')

    expectOk(await scan({ cwd: '/tmp', production: false, cliIgnores: [], configPath: undefined }))

    const [lastCall] = mockCalls.slice(-1)
    const [callArgs] = lastCall ?? []

    expect(callArgs?.[1]).toStrictEqual(['audit', '--json'])
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
