import type { ScanResult } from './types/index.js'
import { SCHEMA_VERSION, APP_NAME } from './constants.js'

export const formatJson = (result: ScanResult): string =>
  JSON.stringify(
    {
      schemaVersion: SCHEMA_VERSION,
      scanner: APP_NAME,
      metadata: {
        packageManager: result.packageManager,
        ...result.metadata,
      },
      vulnerabilities: result.vulnerabilities,
      exceptions: result.exceptions,
      unhandled: result.unhandled,
    },
    undefined,
    2,
  )
