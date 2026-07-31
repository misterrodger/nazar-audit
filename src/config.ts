import * as v from 'valibot'
import { parse as parseYaml } from 'yaml'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { type NazarConfig, type Result, ok, err } from './types.js'

const ExceptionEntrySchema = v.object({
  id: v.optional(v.string()),
  module: v.optional(v.string()),
  active: v.optional(v.boolean()),
  expiry: v.optional(v.string()),
  notes: v.optional(v.string()),
  addedBy: v.optional(v.string()),
})

const NazarConfigSchema = v.object({
  level: v.optional(v.picklist(['info', 'low', 'moderate', 'high', 'critical'])),
  format: v.optional(v.picklist(['table', 'json'])),
  filterTable: v.optional(v.picklist(['info', 'low', 'moderate', 'high', 'critical'])),
  production: v.optional(v.boolean()),
  exceptions: v.optional(v.array(ExceptionEntrySchema)),
})

const validateConfig = (raw: unknown): Result<NazarConfig> => {
  const result = v.safeParse(NazarConfigSchema, raw)

  return result.success
    ? ok(result.output as NazarConfig)
    : err(`Invalid .nazar.yml: ${result.issues.map((i) => i.message).join(', ')}`)
}

export const parseConfigYaml = (yamlString: string): Result<NazarConfig> => {
  const raw: unknown = parseYaml(yamlString)

  return !raw ? ok({}) : validateConfig(raw)
}

export const loadConfigFile = (cwd: string): Result<NazarConfig> => {
  const configPath = join(cwd, '.nazar.yml')

  return !existsSync(configPath) ? ok({}) : parseConfigYaml(readFileSync(configPath, 'utf-8'))
}
