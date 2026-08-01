import { defineCommand, runMain } from 'citty'
import { type Result, type Severity, SEVERITY_ORDER, isSeverity, ok, err } from './types.js'
import { scan, passesThreshold } from './scan.js'
import { formatTable } from './report-table.js'
import { formatJson } from './report-json.js'
import { VERSION } from './index.js'
import { getBanner } from './banner.js'

const VALID_FORMATS = ['table', 'json'] as const
type OutputFormat = (typeof VALID_FORMATS)[number]

const isOutputFormat = (value: string): value is OutputFormat =>
  (VALID_FORMATS as ReadonlyArray<string>).includes(value)

const parseSeverity = (name: string, value: string | undefined): Result<Severity | undefined> =>
  value === undefined
    ? ok(undefined)
    : isSeverity(value)
      ? ok(value)
      : err(`Invalid ${name}: "${value}". Must be one of: ${SEVERITY_ORDER.join(', ')}`)

const parseFormat = (value: string | undefined): Result<OutputFormat> =>
  value === undefined
    ? ok('table')
    : isOutputFormat(value)
      ? ok(value)
      : err(`Invalid --format: "${value}". Must be one of: ${VALID_FORMATS.join(', ')}`)

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

const EXIT_VULNERABILITIES = 1
const EXIT_ERROR = 2

const main = defineCommand({
  meta: {
    name: 'nazar-audit',
    version: VERSION,
    description: 'A modern, security-conscious package vulnerability scanner',
  },
  args: {
    level: {
      type: 'string',
      alias: 'l',
      description: 'Minimum severity for non-zero exit (info|low|moderate|high|critical)',
    },
    format: {
      type: 'string',
      alias: 'f',
      description: 'Output format: table, json (default: table)',
    },
    'filter-table': {
      type: 'string',
      description: 'Filter table display by minimum severity',
    },
    ignore: {
      type: 'string',
      alias: 'i',
      description: 'Advisory IDs to ignore, comma-separated',
    },
    production: {
      type: 'boolean',
      alias: 'p',
      description: 'Skip devDependencies (passes --omit=dev to npm)',
      default: false,
    },
    timeout: {
      type: 'string',
      description: 'npm audit timeout in seconds (default: 60)',
    },
    config: {
      type: 'string',
      description: 'Path to config file (default: .nazar.yml in cwd)',
    },
  },
  /* eslint-disable functional/no-expression-statements, functional/no-conditional-statements, functional/no-try-statements, functional/immutable-data, no-console */
  run: async ({ args }) => {
    try {
      const levelResult = parseSeverity('--level', args.level)
      if (!levelResult.ok) {
        console.error(`Error: ${levelResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const filterTableResult = parseSeverity('--filter-table', args['filter-table'])
      if (!filterTableResult.ok) {
        console.error(`Error: ${filterTableResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const formatResult = parseFormat(args.format)
      if (!formatResult.ok) {
        console.error(`Error: ${formatResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      if (formatResult.data === 'table') {
        console.log(getBanner())
        console.log()
      }

      const timeoutResult = parseTimeout(args.timeout)
      if (!timeoutResult.ok) {
        console.error(`Error: ${timeoutResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const cliIgnores = parseIgnores(args.ignore)

      const result = await scan({
        cwd: process.cwd(),
        production: args.production,
        cliIgnores,
        configPath: args.config,
        timeoutMs: timeoutResult.data,
      })

      if (!result.ok) {
        console.error(`Error: ${result.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const output =
        formatResult.data === 'json'
          ? formatJson(result.data)
          : formatTable(result.data, filterTableResult.data)

      console.log(output)

      if (!passesThreshold(result.data, levelResult.data)) {
        process.exitCode = EXIT_VULNERABILITIES
      }
    } catch (error: unknown) {
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = EXIT_ERROR
    }
  },
  /* eslint-enable functional/no-expression-statements, functional/no-conditional-statements, functional/no-try-statements, functional/immutable-data, no-console */
})

// eslint-disable-next-line functional/no-expression-statements
void runMain(main)
