import {
  type FailOn,
  type NazarConfig,
  type OutputFormat,
  type Result,
  type Severity,
  SEVERITY_ORDER,
  FAIL_ON_VALUES,
  VALID_FORMATS,
  isSeverity,
  isFailOn,
  ok,
  err,
} from './types/index.js'

const isOutputFormat = (value: string): value is OutputFormat =>
  (VALID_FORMATS as ReadonlyArray<string>).includes(value)

const parseSeverity = (name: string, value: string | undefined): Result<Severity | undefined> =>
  value === undefined
    ? ok(undefined)
    : isSeverity(value)
      ? ok(value)
      : err(`Invalid ${name}: "${value}". Must be one of: ${SEVERITY_ORDER.join(', ')}`)

const parseFormat = (value: string | undefined): Result<OutputFormat | undefined> =>
  value === undefined
    ? ok(undefined)
    : isOutputFormat(value)
      ? ok(value)
      : err(`Invalid --format: "${value}". Must be one of: ${VALID_FORMATS.join(', ')}`)

const parseFailOn = (value: string | undefined): Result<FailOn | undefined> =>
  value === undefined
    ? ok(undefined)
    : isFailOn(value)
      ? ok(value)
      : err(`Invalid --fail-on: "${value}". Must be one of: ${FAIL_ON_VALUES.join(', ')}`)

const parseIgnores = (value: string | undefined): ReadonlyArray<string> =>
  value !== undefined
    ? value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : []

const parseTimeout = (value: string | undefined): Result<number | undefined> =>
  value === undefined
    ? ok(undefined)
    : Number.isFinite(Number(value)) && Number(value) > 0
      ? ok(Number(value) * 1000)
      : err(`Invalid --timeout: "${value}". Must be a positive number (seconds)`)

export type CliArgs = Readonly<{
  level: string | undefined
  format: string | undefined
  filterTable: string | undefined
  production: boolean | undefined
  failOn: string | undefined
  timeout: string | undefined
  ignore: string | undefined
}>

export type ResolvedOptions = Readonly<{
  level: Severity | undefined
  format: OutputFormat
  filterTable: Severity | undefined
  production: boolean
  failOn: FailOn | undefined
  timeoutMs: number | undefined
  cliIgnores: ReadonlyArray<string>
}>

export const resolveOptions = (args: CliArgs, config: NazarConfig): Result<ResolvedOptions> => {
  const levelResult = parseSeverity('--level', args.level)
  const filterTableResult = parseSeverity('--filter-table', args.filterTable)
  const formatResult = parseFormat(args.format)
  const failOnResult = parseFailOn(args.failOn)
  const timeoutResult = parseTimeout(args.timeout)

  return !levelResult.ok
    ? err(levelResult.error)
    : !filterTableResult.ok
      ? err(filterTableResult.error)
      : !formatResult.ok
        ? err(formatResult.error)
        : !failOnResult.ok
          ? err(failOnResult.error)
          : !timeoutResult.ok
            ? err(timeoutResult.error)
            : ok({
                level: levelResult.data ?? config.level,
                format: formatResult.data ?? config.format ?? 'table',
                filterTable: filterTableResult.data ?? config.filterTable,
                production: args.production ?? config.production ?? false,
                failOn: failOnResult.data ?? config.failOn,
                timeoutMs: timeoutResult.data,
                cliIgnores: parseIgnores(args.ignore),
              })
}
