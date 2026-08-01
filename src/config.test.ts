import { type NazarConfig, type Result } from './types.js'
import { parseConfigYaml, loadConfigFile } from './config.js'

const expectOkConfig = (result: Result<NazarConfig>): NazarConfig => {
  expect(result.ok).toBe(true)

  return (result as { ok: true; data: NazarConfig }).data
}

const expectErrMessage = (result: Result<NazarConfig>): string => {
  expect(result.ok).toBe(false)

  return (result as { ok: false; error: string }).error
}

describe('parseConfigYaml', () => {
  it('parses a full config with all fields', () => {
    const yaml = `
level: high
format: json
filterTable: moderate
production: true
exceptions:
  - id: "GHSA-xxxx-yyyy-zzzz"
    active: true
    expiry: "2025-06-01"
    notes: "No impact"
    addedBy: "jrodger"
  - module: "minimist"
    notes: "Dev-only dependency"
`
    const config = expectOkConfig(parseConfigYaml(yaml))

    expect(config.level).toBe('high')
    expect(config.format).toBe('json')
    expect(config.filterTable).toBe('moderate')
    expect(config.production).toBe(true)
    expect(config.exceptions).toHaveLength(2)
    expect(config.exceptions![0]).toMatchObject({
      id: 'GHSA-xxxx-yyyy-zzzz',
      active: true,
      expiry: '2025-06-01',
      notes: 'No impact',
      addedBy: 'jrodger',
    })
    expect(config.exceptions![1]).toMatchObject({
      module: 'minimist',
      notes: 'Dev-only dependency',
    })
  })

  it('parses a minimal config with only exceptions', () => {
    const config = expectOkConfig(
      parseConfigYaml(`
exceptions:
  - id: "GHSA-test-test-test"
`),
    )

    expect(config.level).toBeUndefined()
    expect(config.exceptions).toHaveLength(1)
  })

  it('returns empty config for empty YAML', () => {
    const config = expectOkConfig(parseConfigYaml(''))

    expect(config).toStrictEqual({})
  })

  it('returns empty config for blank YAML', () => {
    const config = expectOkConfig(parseConfigYaml('   \n  \n  '))

    expect(config).toStrictEqual({})
  })

  it('returns empty config for YAML document separator only', () => {
    const config = expectOkConfig(parseConfigYaml('---'))

    expect(config).toStrictEqual({})
  })

  it('rejects invalid severity value', () => {
    const error = expectErrMessage(parseConfigYaml('level: extreme'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects invalid format value', () => {
    const error = expectErrMessage(parseConfigYaml('format: xml'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects non-object YAML content', () => {
    const error = expectErrMessage(parseConfigYaml('42'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects YAML scalar false', () => {
    const error = expectErrMessage(parseConfigYaml('false'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects YAML scalar 0', () => {
    const error = expectErrMessage(parseConfigYaml('0'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects exception with wrong type for active', () => {
    const error = expectErrMessage(
      parseConfigYaml(`
exceptions:
  - id: "GHSA-test"
    active: "yes"
`),
    )

    expect(error).toContain('Invalid .nazar.yml')
  })

  it.each(['info', 'low', 'moderate', 'high', 'critical'] as const)(
    'accepts %s as a valid severity level',
    (level) => {
      const config = expectOkConfig(parseConfigYaml(`level: ${level}`))

      expect(config.level).toBe(level)
    },
  )
})

describe('loadConfigFile', () => {
  it('returns empty config when .nazar.yml does not exist', () => {
    const config = expectOkConfig(loadConfigFile('/nonexistent/path'))

    expect(config).toStrictEqual({})
  })
})
