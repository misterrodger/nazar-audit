import { promisify } from 'node:util'
import { execFile as execFileCb } from 'node:child_process'
import {
  type ExceptionEntry,
  type FixAvailability,
  type NazarConfig,
  type Result,
  type ScanResult,
  type Severity,
  type Vulnerability,
  severityIndex,
  ok,
  err,
} from './types.js'
import { parseNpmAuditJson } from './parse-npm.js'
import { loadConfigFile, loadConfigPath } from './config.js'
import { applyExceptions } from './exceptions.js'

const execFileAsync = promisify(execFileCb)
const MAX_BUFFER = 50 * 1024 * 1024
const DEFAULT_TIMEOUT_MS = 60_000

type ScanOptions = Readonly<{
  cwd: string
  production: boolean
  cliIgnores: ReadonlyArray<string>
  configPath: string | undefined
  timeoutMs?: number | undefined
}>

const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm'

const buildNpmArgs = (production: boolean): ReadonlyArray<string> =>
  production ? ['audit', '--json', '--omit=dev'] : ['audit', '--json']

type ExecError = Error & Readonly<{ stdout: string; stderr: string }>

const isExecError = (e: unknown): e is ExecError =>
  e instanceof Error && 'stdout' in e && 'stderr' in e

const extractErrorDetail = (error: unknown): Readonly<{ stdout: string; message: string }> =>
  isExecError(error)
    ? { stdout: error.stdout, message: error.stderr || error.message }
    : {
        stdout: '',
        message: error instanceof Error ? error.message : String(error),
      }

const runNpmAudit = (
  cwd: string,
  args: ReadonlyArray<string>,
  timeoutMs: number,
): Promise<Result<string>> =>
  execFileAsync(NPM_BIN, [...args], {
    cwd,
    maxBuffer: MAX_BUFFER,
    timeout: timeoutMs,
    killSignal: 'SIGTERM',
    ...(process.platform === 'win32' ? { shell: true } : {}),
  }).then(
    ({ stdout }) => (stdout ? ok(stdout) : err('npm audit produced no output')),
    (error: unknown) => {
      const { stdout, message } = extractErrorDetail(error)

      return stdout ? ok(stdout) : err(`npm audit failed: ${message}`)
    },
  )

const EMPTY_COUNTS = {
  info: 0,
  low: 0,
  moderate: 0,
  high: 0,
  critical: 0,
} as const satisfies Record<Severity, number>

const countBySeverity = (
  vulns: ReadonlyArray<Vulnerability>,
): Readonly<Record<Severity, number>> => {
  /* eslint-disable functional/no-expression-statements, functional/immutable-data, functional/no-loop-statements -- mutable accumulator for perf */
  const counts: Record<Severity, number> = { ...EMPTY_COUNTS }
  for (const v of vulns) {
    counts[v.severity] += 1
  }

  return counts
}

const isFixable = (fix: FixAvailability): boolean => fix.kind !== 'none'

const cliIgnoresToExceptions = (ignores: ReadonlyArray<string>): ReadonlyArray<ExceptionEntry> =>
  ignores.map((id) => ({ id }))

const buildScanResult = (
  vulns: ReadonlyArray<Vulnerability>,
  exceptions: ReadonlyArray<ExceptionEntry>,
): ScanResult => {
  const exceptionResult = applyExceptions(vulns, exceptions)

  return {
    packageManager: 'npm',
    vulnerabilities: vulns,
    metadata: {
      total: vulns.length,
      severityCounts: countBySeverity(vulns),
      directCount: vulns.filter((v) => v.isDirect).length,
      transitiveCount: vulns.filter((v) => !v.isDirect).length,
      fixableCount: vulns.filter((v) => isFixable(v.fixAvailable)).length,
      unfixableCount: vulns.filter((v) => !isFixable(v.fixAvailable)).length,
    },
    exceptions: {
      matched: exceptionResult.matched,
      unused: exceptionResult.unused,
      expired: exceptionResult.expired,
    },
    unhandled: exceptionResult.unhandled,
  }
}

const buildFromJson = (
  jsonString: string,
  configExceptions: ReadonlyArray<ExceptionEntry>,
  cliIgnores: ReadonlyArray<string>,
): Result<ScanResult> => {
  const parseResult = parseNpmAuditJson(jsonString)

  return !parseResult.ok
    ? err(parseResult.error)
    : ok(
        buildScanResult(parseResult.data, [
          ...configExceptions,
          ...cliIgnoresToExceptions(cliIgnores),
        ]),
      )
}

const scanWithConfig = async (
  options: ScanOptions,
  config: NazarConfig,
): Promise<Result<ScanResult>> => {
  const configTimeoutMs =
    config.timeoutSeconds !== undefined ? config.timeoutSeconds * 1000 : undefined
  const timeoutMs = options.timeoutMs ?? configTimeoutMs ?? DEFAULT_TIMEOUT_MS
  const auditResult = await runNpmAudit(options.cwd, buildNpmArgs(options.production), timeoutMs)

  return !auditResult.ok
    ? err(auditResult.error)
    : buildFromJson(auditResult.data, config.exceptions ?? [], options.cliIgnores)
}

const loadConfig = (options: ScanOptions): Result<NazarConfig> =>
  options.configPath !== undefined
    ? loadConfigPath(options.configPath)
    : loadConfigFile(options.cwd)

export const scan = async (options: ScanOptions): Promise<Result<ScanResult>> => {
  const configResult = loadConfig(options)

  return !configResult.ok ? err(configResult.error) : scanWithConfig(options, configResult.data)
}

export const passesThreshold = (result: ScanResult, level: Severity | undefined): boolean => {
  const minIndex = severityIndex(level ?? 'low')

  return result.unhandled.every((v) => severityIndex(v.severity) < minIndex)
}
