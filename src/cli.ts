import { defineCommand, runMain } from 'citty'
import { type Severity, SEVERITY_ORDER } from './types.js'
import { scan, meetsThreshold } from './scan.js'
import { formatTable } from './report-table.js'
import { formatJson } from './report-json.js'
import { VERSION } from './index.js'

const isSeverity = (value: string): value is Severity =>
  (SEVERITY_ORDER as ReadonlyArray<string>).includes(value)

const parseSeverity = (value: string | undefined): Severity | undefined =>
  value !== undefined && isSeverity(value) ? value : undefined

const parseIgnores = (value: string | undefined): ReadonlyArray<string> =>
  value !== undefined
    ? value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : []

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
    config: {
      type: 'string',
      description: 'Path to config file (default: .nazar.yml in cwd)',
    },
  },
  /* eslint-disable functional/no-expression-statements, functional/no-conditional-statements, functional/no-try-statements, functional/immutable-data, no-console */
  run: async ({ args }) => {
    try {
      const level = parseSeverity(args.level)
      const filterTable = parseSeverity(args['filter-table'])
      const format = args.format === 'json' ? 'json' : 'table'
      const cliIgnores = parseIgnores(args.ignore)

      const result = await scan({
        cwd: process.cwd(),
        production: args.production,
        cliIgnores,
        configPath: args.config,
      })

      if (!result.ok) {
        console.error(`Error: ${result.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const output =
        format === 'json' ? formatJson(result.data) : formatTable(result.data, filterTable)

      console.log(output)

      if (!meetsThreshold(result.data, level)) {
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
