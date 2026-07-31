import { promisify } from 'node:util'
import { execFile as execFileCb } from 'node:child_process'
import {
  type ExceptionEntry,
  type FixAvailability,
  type Result,
  type ScanResult,
  type Severity,
  type Vulnerability,
  SEVERITY_ORDER,
  ok,
  err,
} from './types.js'
import { parseNpmAuditJson } from './parse-npm.js'
import { loadConfigFile } from './config.js'
import { applyExceptions } from './exceptions.js'

const execFileAsync = promisify(execFileCb)
const MAX_BUFFER = 50 * 1024 * 1024

type ScanOptions = Readonly<{
  cwd: string
  production: boolean
  cliIgnores: ReadonlyArray<string>
  configPath: string | undefined
}>

const buildNpmArgs = (production: boolean): ReadonlyArray<string> =>
  production ? ['audit', '--json', '--omit=dev'] : ['audit', '--json']

const extractStdout = (error: unknown): string =>
  (error as Readonly<{ stdout?: string }>).stdout ?? ''

const runNpmAudit = (cwd: string, args: ReadonlyArray<string>): Promise<Result<string>> =>
  execFileAsync('npm', [...args], { cwd, maxBuffer: MAX_BUFFER }).then(
    ({ stdout }) => (stdout ? ok(stdout) : err('npm audit produced no output')),
    (error: unknown) => {
      const stdout = extractStdout(error)
      return stdout ? ok(stdout) : err('npm audit produced no output')
    },
  )

const isSeverity = (value: string): value is Severity =>
  (SEVERITY_ORDER as ReadonlyArray<string>).includes(value)

const severityIndex = (severity: Severity): number => SEVERITY_ORDER.indexOf(severity)

const countBySeverity = (
  vulns: ReadonlyArray<Vulnerability>,
): Readonly<Record<Severity, number>> => ({
  info: vulns.filter((v) => v.severity === 'info').length,
  low: vulns.filter((v) => v.severity === 'low').length,
  moderate: vulns.filter((v) => v.severity === 'moderate').length,
  high: vulns.filter((v) => v.severity === 'high').length,
  critical: vulns.filter((v) => v.severity === 'critical').length,
})

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
  configExceptions: ReadonlyArray<ExceptionEntry>,
): Promise<Result<ScanResult>> => {
  const auditResult = await runNpmAudit(options.cwd, buildNpmArgs(options.production))

  return !auditResult.ok
    ? err(auditResult.error)
    : buildFromJson(auditResult.data, configExceptions, options.cliIgnores)
}

export const scan = async (options: ScanOptions): Promise<Result<ScanResult>> => {
  const configResult = loadConfigFile(options.configPath ?? options.cwd)

  return !configResult.ok
    ? err(configResult.error)
    : scanWithConfig(options, configResult.data.exceptions ?? [])
}

export const meetsThreshold = (result: ScanResult, level: Severity | undefined): boolean => {
  const minIndex = severityIndex(level ?? 'low')

  return result.unhandled.every(
    (v) => !isSeverity(v.severity) || severityIndex(v.severity) < minIndex,
  )
}
