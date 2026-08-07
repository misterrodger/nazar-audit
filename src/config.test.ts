import { parseConfigYaml, loadConfigFile, resolveConfig } from './config.js'
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

    expect(config).toMatchInlineSnapshot(`
      {
        "exceptions": [
          {
            "active": true,
            "addedBy": "jrodger",
            "expiry": "2025-06-01",
            "id": "GHSA-xxxx-yyyy-zzzz",
            "notes": "No impact",
          },
          {
            "module": "minimist",
            "notes": "Dev-only dependency",
          },
        ],
        "failOn": undefined,
        "filterTable": "moderate",
        "format": "json",
        "level": "high",
        "production": true,
        "timeoutSeconds": undefined,
      }
    `)
  })

  it('parses a minimal config with only exceptions', () => {
    const config = expectOk(
      parseConfigYaml(`
exceptions:
  - id: "GHSA-test-test-test"
`),
    )

    expect(config).toMatchInlineSnapshot(`
      {
        "exceptions": [
          {
            "id": "GHSA-test-test-test",
          },
        ],
        "failOn": undefined,
        "filterTable": undefined,
        "format": undefined,
        "level": undefined,
        "production": undefined,
        "timeoutSeconds": undefined,
      }
    `)
  })

  it('accepts string and numeric exception ids', () => {
    const config = expectOk(
      parseConfigYaml(`
exceptions:
  - id: 123
  - id: "550e8400-e29b-41d4-a716-446655440000"
  - id: "GHSA-xxxx-yyyy-zzzz"
`),
    )

    expect(config.exceptions).toStrictEqual([
      { id: '123' },
      { id: '550e8400-e29b-41d4-a716-446655440000' },
      { id: 'GHSA-xxxx-yyyy-zzzz' },
    ])
  })

  it('rejects non-string and non-numeric exception ids', () => {
    const error = expectErr(
      parseConfigYaml(`
exceptions:
  - id: true
`),
    )

    expect(error).toContain('Invalid .nazar.yml')
  })

  it('rejects non-integer numeric exception ids', () => {
    const error = expectErr(
      parseConfigYaml(`
exceptions:
  - id: 123.4
`),
    )

    expect(error).toContain('Invalid .nazar.yml')
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

    expect(error).toMatchInlineSnapshot(
      `"Invalid .nazar.yml: Invalid type: Expected ("info" | "low" | "moderate" | "high" | "critical") but received "extreme""`,
    )
  })

  it('rejects invalid format value', () => {
    const error = expectErr(parseConfigYaml('format: xml'))

    expect(error).toMatchInlineSnapshot(
      `"Invalid .nazar.yml: Invalid type: Expected ("table" | "json") but received "xml""`,
    )
  })

  it('rejects non-object YAML content', () => {
    const error = expectErr(parseConfigYaml('42'))

    expect(error).toMatchInlineSnapshot(
      `"Invalid .nazar.yml: Invalid type: Expected Object but received 42"`,
    )
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

  it('joins multiple validation errors with comma separator', () => {
    const error = expectErr(
      parseConfigYaml(`
level: bad
format: bad
`),
    )

    expect(error).toContain(', ')
    expect(error).toMatch(/Invalid .nazar.yml:.*,.*/)
  })

  describe('timeoutSeconds validation', () => {
    it('accepts a positive number', () => {
      const config = expectOk(parseConfigYaml('timeoutSeconds: 120'))

      expect(config.timeoutSeconds).toBe(120)
    })

    it('rejects zero', () => {
      const error = expectErr(parseConfigYaml('timeoutSeconds: 0'))

      expect(error).toContain('Invalid .nazar.yml')
    })

    it('rejects negative values', () => {
      const error = expectErr(parseConfigYaml('timeoutSeconds: -5'))

      expect(error).toContain('Invalid .nazar.yml')
    })

    it('rejects string values', () => {
      const error = expectErr(parseConfigYaml('timeoutSeconds: "sixty"'))

      expect(error).toContain('Invalid .nazar.yml')
    })
  })

  describe('filterTable validation', () => {
    it.each(['info', 'low', 'moderate', 'high', 'critical'] as const)(
      'accepts %s as a valid filterTable value',
      (filter) => {
        const config = expectOk(parseConfigYaml(`filterTable: ${filter}`))

        expect(config.filterTable).toBe(filter)
      },
    )

    it('rejects invalid filterTable value', () => {
      const error = expectErr(parseConfigYaml('filterTable: extreme'))

      expect(error).toContain('Invalid .nazar.yml')
    })
  })

  describe('format validation', () => {
    it.each(['table', 'json'] as const)('accepts %s as a valid format', (format) => {
      const config = expectOk(parseConfigYaml(`format: ${format}`))

      expect(config.format).toBe(format)
    })
  })

  describe('failOn validation', () => {
    it.each(['all', 'upgradable', 'patchable'] as const)(
      'accepts %s as a valid failOn value',
      (failOn) => {
        const config = expectOk(parseConfigYaml(`failOn: ${failOn}`))

        expect(config.failOn).toBe(failOn)
      },
    )

    it('rejects invalid failOn value', () => {
      const error = expectErr(parseConfigYaml('failOn: extreme'))

      expect(error).toContain('Invalid .nazar.yml')
    })
  })
})

describe('loadConfigFile', () => {
  it('returns empty config when .nazar.yml does not exist', () => {
    const config = expectOk(loadConfigFile('/nonexistent/path'))

    expect(config).toStrictEqual({})
  })
})

describe('resolveConfig', () => {
  it('falls back to loadConfigFile when no configPath is given', () => {
    const config = expectOk(resolveConfig('/nonexistent/path', undefined))

    expect(config).toStrictEqual({})
  })

  it('returns err when the given configPath does not exist', () => {
    const error = expectErr(resolveConfig('/tmp', '/nonexistent/path/.nazar.yml'))

    expect(error).toContain('Config file not found')
  })
})
