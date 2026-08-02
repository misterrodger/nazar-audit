import pkg from '../package.json' with { type: 'json' }

const { version } = pkg

export const APP_NAME = 'nazar-audit'
export const VERSION: string = version

export const EXIT_VULNERABILITIES = 1
export const EXIT_ERROR = 2

export const MAX_BUFFER = 50 * 1024 * 1024
export const DEFAULT_TIMEOUT_MS = 60_000

export const SCHEMA_VERSION = 1
export const AUDIT_REPORT_VERSION = 2
