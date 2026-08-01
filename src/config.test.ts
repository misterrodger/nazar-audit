import { parseConfigYaml, loadConfigFile } from './config.js'
import { expectOk, expectErr } from './test-helpers.js'

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
    const config = expectOk(parseConfigYaml(yaml))

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
    const config = expectOk(
      parseConfigYaml(`
exceptions:
  - id: "GHSA-test-test-test"
`),
    )

    expect(config.level).toBeUndefined()
    expect(config.exceptions).toHaveLength(1)
  })

  it('returns empty config for empty YAML', () => {
    const config = expectOk(parseConfigYaml(''))

    expect(config).toStrictEqual({})
  })

  it('returns empty config for blank YAML', () => {
    const config = expectOk(parseConfigYaml('   \n  \n  '))

    expect(config).toStrictEqual({})
  })

  it('returns empty config for YAML document separator only', () => {
    const config = expectOk(parseConfigYaml('---'))

    expect(config).toStrictEqual({})
  })

  it('rejects invalid severity value', () => {
    const error = expectErr(parseConfigYaml('level: extreme'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects invalid format value', () => {
    const error = expectErr(parseConfigYaml('format: xml'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects non-object YAML content', () => {
    const error = expectErr(parseConfigYaml('42'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects YAML scalar false', () => {
    const error = expectErr(parseConfigYaml('false'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects YAML scalar 0', () => {
    const error = expectErr(parseConfigYaml('0'))

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects exception with wrong type for active', () => {
    const error = expectErr(
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
      const config = expectOk(parseConfigYaml(`level: ${level}`))

      expect(config.level).toBe(level)
    },
  )
})

describe('loadConfigFile', () => {
  it('returns empty config when .nazar.yml does not exist', () => {
    const config = expectOk(loadConfigFile('/nonexistent/path'))

    expect(config).toStrictEqual({})
  })
})
