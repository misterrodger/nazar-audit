import * as v from 'valibot'
import { parse as parseYaml } from 'yaml'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  type NazarConfig,
  type Result,
  SEVERITY_ORDER,
  FAIL_ON_VALUES,
  VALID_FORMATS,
  ok,
  err,
} from './types/index.js'

const ExceptionEntrySchema = v.object({
  id: v.optional(v.string()),
  module: v.optional(v.string()),
  active: v.optional(v.boolean()),
  expiry: v.optional(v.string()),
  notes: v.optional(v.string()),
  addedBy: v.optional(v.string()),
})

const NazarConfigSchema = v.object({
  level: v.optional(v.picklist([...SEVERITY_ORDER])),
  failOn: v.optional(v.picklist([...FAIL_ON_VALUES])),
  format: v.optional(v.picklist([...VALID_FORMATS])),
  filterTable: v.optional(v.picklist([...SEVERITY_ORDER])),
  production: v.optional(v.boolean()),
  timeoutSeconds: v.optional(v.pipe(v.number(), v.minValue(1))),
  exceptions: v.optional(v.array(ExceptionEntrySchema)),
})

type RawNazarConfig = v.InferOutput<typeof NazarConfigSchema>

const toNazarConfig = (raw: RawNazarConfig): NazarConfig => ({
  level: raw.level,
  failOn: raw.failOn,
  format: raw.format,
  filterTable: raw.filterTable,
  production: raw.production,
  timeoutSeconds: raw.timeoutSeconds,
  exceptions: raw.exceptions,
})

const validateConfig = (raw: unknown): Result<NazarConfig> => {
  const result = v.safeParse(NazarConfigSchema, raw)

  return result.success
    ? ok(toNazarConfig(result.output))
    : err(`Invalid .nazar.yml: ${result.issues.map((i) => i.message).join(', ')}`)
}

export const parseConfigYaml = (yamlString: string): Result<NazarConfig> => {
  const raw: unknown = parseYaml(yamlString)

  // eslint-disable-next-line no-restricted-syntax -- YAML parser returns null for empty documents
  return raw === undefined || raw === null ? ok({}) : validateConfig(raw)
}

export const loadConfigFile = (cwd: string): Result<NazarConfig> => {
  const configPath = join(cwd, '.nazar.yml')

  return !existsSync(configPath) ? ok({}) : parseConfigYaml(readFileSync(configPath, 'utf-8'))
}

export const loadConfigPath = (filePath: string): Result<NazarConfig> =>
  !existsSync(filePath)
    ? err(`Config file not found: ${filePath}`)
    : parseConfigYaml(readFileSync(filePath, 'utf-8'))

export const resolveConfig = (cwd: string, configPath: string | undefined): Result<NazarConfig> =>
  configPath !== undefined ? loadConfigPath(configPath) : loadConfigFile(cwd)
