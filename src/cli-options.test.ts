import { resolveOptions } from './cli-options.js'
import { expectOk, expectErr } from './test-helpers.js'

const NO_ARGS = {
  level: undefined,
  format: undefined,
  filterTable: undefined,
  production: undefined,
  failOn: undefined,
  timeout: undefined,
  ignore: undefined,
}

const NO_CONFIG = {}

describe('resolveOptions', () => {
  it('uses built-in defaults when neither CLI args nor config are set', () => {
    const options = expectOk(resolveOptions(NO_ARGS, NO_CONFIG))

    expect(options).toStrictEqual({
      level: undefined,
      format: 'table',
      filterTable: undefined,
      production: false,
      failOn: undefined,
      timeoutMs: undefined,
      cliIgnores: [],
    })
  })

  it('uses the config value when no CLI flag is given', () => {
    const options = expectOk(
      resolveOptions(NO_ARGS, {
        level: 'high',
        format: 'json',
        filterTable: 'moderate',
        production: true,
        failOn: 'upgradable',
      }),
    )

    expect(options.level).toBe('high')
    expect(options.format).toBe('json')
    expect(options.filterTable).toBe('moderate')
    expect(options.production).toBe(true)
    expect(options.failOn).toBe('upgradable')
  })

  it('prefers the CLI flag over the config value when both are given', () => {
    const options = expectOk(
      resolveOptions(
        { ...NO_ARGS, level: 'critical', format: 'table', production: true, failOn: 'patchable' },
        { level: 'low', format: 'json', production: false, failOn: 'upgradable' },
      ),
    )

    expect(options.level).toBe('critical')
    expect(options.format).toBe('table')
    expect(options.production).toBe(true)
    expect(options.failOn).toBe('patchable')
  })

  it('treats an explicit --no-production as set, overriding a config production: true', () => {
    const options = expectOk(
      resolveOptions({ ...NO_ARGS, production: false }, { production: true }),
    )

    expect(options.production).toBe(false)
  })

  it('rejects an invalid --level without consulting config', () => {
    const error = expectErr(resolveOptions({ ...NO_ARGS, level: 'extreme' }, { level: 'high' }))

    expect(error).toContain('Invalid --level')
  })

  it('rejects an invalid --fail-on value', () => {
    const error = expectErr(resolveOptions({ ...NO_ARGS, failOn: 'extreme' }, NO_CONFIG))

    expect(error).toContain('Invalid --fail-on')
  })

  it('parses comma-separated --ignore into a trimmed list', () => {
    const options = expectOk(
      resolveOptions({ ...NO_ARGS, ignore: 'GHSA-aaaa-bbbb-cccc, GHSA-dddd-eeee-ffff' }, NO_CONFIG),
    )

    expect(options.cliIgnores).toStrictEqual(['GHSA-aaaa-bbbb-cccc', 'GHSA-dddd-eeee-ffff'])
  })
})
