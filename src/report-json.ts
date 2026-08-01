import type { ScanResult } from './types.js'

export const formatJson = (result: ScanResult): string =>
  JSON.stringify(
    {
      schemaVersion: 1,
      scanner: 'nazar-audit',
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
