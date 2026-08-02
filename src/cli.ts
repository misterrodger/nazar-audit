import { defineCommand, runMain } from 'citty'
import { resolveOptions } from './cli-options.js'
import { scan, passesThreshold } from './scan.js'
import { resolveConfig } from './config.js'
import { formatTable } from './report-table.js'
import { formatJson } from './report-json.js'
import { APP_NAME, VERSION, EXIT_VULNERABILITIES, EXIT_ERROR } from './constants.js'
import { getBanner } from './banner.js'
import { createSpinner } from 'nanospinner'

const main = defineCommand({
  meta: {
    name: APP_NAME,
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
      description: 'Skip devDependencies (passes --omit=dev to npm; default: false)',
    },
    'fail-on': {
      type: 'string',
      description:
        'Which vulnerabilities count toward exit code: all (default), upgradable, patchable',
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
  /* eslint-disable functional/no-expression-statements, functional/no-conditional-statements, functional/no-try-statements, functional/immutable-data, functional/no-let, no-console */
  run: async ({ args }) => {
    let spinner: ReturnType<typeof createSpinner> | undefined
    try {
      const configResult = resolveConfig(process.cwd(), args.config)
      if (!configResult.ok) {
        console.error(`Error: ${configResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      const optionsResult = resolveOptions(
        {
          level: args.level,
          format: args.format,
          filterTable: args['filter-table'],
          production: args.production,
          failOn: args['fail-on'],
          timeout: args.timeout,
          ignore: args.ignore,
        },
        configResult.data,
      )
      if (!optionsResult.ok) {
        console.error(`Error: ${optionsResult.error}`)
        process.exitCode = EXIT_ERROR
        return
      }
      const { data: options } = optionsResult

      if (options.format === 'table') {
        console.log(getBanner())
        console.log()
      }

      spinner = options.format === 'table' ? createSpinner('Scanning...').start() : undefined

      const result = await scan({
        cwd: process.cwd(),
        production: options.production,
        cliIgnores: options.cliIgnores,
        config: configResult.data,
        timeoutMs: options.timeoutMs,
      })

      if (!result.ok) {
        if (spinner) spinner.error({ text: 'Scan failed' })
        console.error(`Error: ${result.error}`)
        process.exitCode = EXIT_ERROR
        return
      }

      if (spinner) spinner.success({ text: 'Scan complete' })

      const output =
        options.format === 'json'
          ? formatJson(result.data)
          : formatTable(result.data, options.filterTable)

      console.log(output)

      if (!passesThreshold(result.data, options.level, options.failOn)) {
        process.exitCode = EXIT_VULNERABILITIES
      }
    } catch (error: unknown) {
      if (spinner) spinner.error()
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = EXIT_ERROR
    }
  },
  /* eslint-enable functional/no-expression-statements, functional/no-conditional-statements, functional/no-try-statements, functional/immutable-data, functional/no-let, no-console */
})

// eslint-disable-next-line functional/no-expression-statements
void runMain(main)
