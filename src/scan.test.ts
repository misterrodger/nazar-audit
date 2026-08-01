import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { vi } from 'vitest'
import { makeVuln, makeScanResult, expectOk, expectErr } from './test-helpers.js'

const mockState = { stdout: '', shouldError: false }

vi.mock('node:child_process', () => {
  const execFileMock = vi.fn()

  const promisified = () =>
    mockState.shouldError
      ? Promise.reject(
          Object.assign(new Error('npm audit found vulnerabilities'), {
            stdout: mockState.stdout,
            stderr: '',
          }),
        )
      : Promise.resolve({ stdout: mockState.stdout, stderr: '' })

  // @ts-expect-error -- promisify reads this symbol to use our mock
  execFileMock[Symbol.for('nodejs.util.promisify.custom')] = promisified

  return { execFile: execFileMock }
})

const fixtureDir = join(import.meta.dirname, 'fixtures')
const readFixture = (name: string): string => readFileSync(join(fixtureDir, name), 'utf-8')

const setMockAudit = (stdout: string, shouldError = false): void => {
  mockState.stdout = stdout
  mockState.shouldError = shouldError
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

    expect(result.packageManager).toBe('npm')
    expect(result.vulnerabilities.length).toBeGreaterThan(0)
    expect(result.metadata.total).toBeGreaterThan(0)
    expect(result.unhandled.length).toBeGreaterThan(0)
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

    expect(error).toContain('no output')
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
    const result = makeScanResult({
      unhandled: [makeVuln({ severity: 'low' })],
    })

    expect(passesThreshold(result, undefined)).toBe(false)
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
