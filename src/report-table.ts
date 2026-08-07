import pc from 'picocolors'
import {
  type Advisory,
  type ScanResult,
  type Vulnerability,
  type Severity,
  type FixAvailability,
  SEVERITY_ORDER,
  severityIndex,
} from './types/index.js'

type TableRow = Readonly<{
  id: string
  severity: Severity
  module: string
  title: string
  paths: string
  fix: string
  url: string
}>

type ColumnWidths = Readonly<{
  id: number
  severity: number
  module: number
  title: number
  paths: number
  fix: number
}>

const COLUMN_GAP = '  '
const [GAP_WIDTH] = [COLUMN_GAP.length] as const
const MIN_TITLE_WIDTH = 20
const MIN_PATHS_WIDTH = 15
const MIN_ID_WIDTH = 2
const MAX_MODULE_WIDTH = 30
const MAX_PATHS_WIDTH = 50
const DEFAULT_TERMINAL_WIDTH = 160
const URL_ESTIMATED_WIDTH = 60
const FIXED_COLUMN_COUNT = 6
const MISSING_ID = '-'

const SEVERITY_DESC = [...SEVERITY_ORDER].reverse()

const SEVERITY_COLORIZERS: Readonly<Record<Severity, (s: string) => string>> = {
  critical: (s: string) => pc.bold(pc.red(s)),
  high: pc.red,
  moderate: pc.yellow,
  low: pc.cyan,
  info: pc.dim,
}

const formatFixAvailability = (fix: FixAvailability): string =>
  fix.kind === 'none'
    ? 'No'
    : fix.kind === 'compatible'
      ? 'Yes'
      : `Breaking (${fix.name}@${fix.version})`

const shortenPath = (nodePath: string): string =>
  nodePath
    .split(/\/?node_modules\//)
    .filter(Boolean)
    .join('->')

const getViaPackages = (vuln: Vulnerability): ReadonlyArray<string> =>
  vuln.via.filter((entry): entry is string => typeof entry === 'string')

const formatPaths = (vuln: Vulnerability): string => {
  const shortened = vuln.nodes.map(shortenPath)
  const viaPackages = getViaPackages(vuln)

  return shortened.length > 0
    ? shortened.join(', ')
    : viaPackages.length > 0
      ? `via ${viaPackages.join(', ')}`
      : ''
}

const formatTransitiveTitle = (vuln: Vulnerability): string => {
  const viaPackages = getViaPackages(vuln)

  return viaPackages.length > 0 ? `(transitive via ${viaPackages.join(', ')})` : '(transitive)'
}

const deduplicateAdvisories = (advisories: ReadonlyArray<Advisory>): ReadonlyArray<Advisory> =>
  advisories.filter(
    (advisory, index, all) => all.findIndex((a) => a.url === advisory.url) === index,
  )

const vulnToRows = (vuln: Vulnerability): ReadonlyArray<TableRow> => {
  const unique = deduplicateAdvisories(vuln.advisories)
  const shared = {
    module: vuln.name,
    paths: formatPaths(vuln),
    fix: formatFixAvailability(vuln.fixAvailable),
  }

  return unique.length > 0
    ? unique.map((advisory) => ({
        ...shared,
        id: String(advisory.source),
        severity: advisory.severity,
        title: advisory.title,
        url: advisory.url,
      }))
    : [
        {
          ...shared,
          id: MISSING_ID,
          severity: vuln.severity,
          title: formatTransitiveTitle(vuln),
          url: '',
        },
      ]
}

const sortBySeverity = (vulns: ReadonlyArray<Vulnerability>): ReadonlyArray<Vulnerability> =>
  SEVERITY_DESC.flatMap((severity) => vulns.filter((v) => v.severity === severity))

const filterRows = (
  rows: ReadonlyArray<TableRow>,
  minSeverity: Severity | undefined,
): ReadonlyArray<TableRow> =>
  minSeverity === undefined
    ? rows
    : rows.filter((r) => severityIndex(r.severity) >= severityIndex(minSeverity))

const padRight = (str: string, width: number): string =>
  str + ' '.repeat(Math.max(0, width - str.length))

const truncate = (str: string, maxLen: number): string =>
  str.length <= maxLen ? str : `${str.slice(0, maxLen - 3)}...`

const splitAtWord = (
  text: string,
  maxWidth: number,
): Readonly<{ line: string; remaining: string }> => {
  const breakAt = text.lastIndexOf(' ', maxWidth)
  const pos = breakAt > 0 ? breakAt : maxWidth

  return { line: text.slice(0, pos), remaining: text.slice(pos + (breakAt > 0 ? 1 : 0)) }
}

const wrapText = (text: string, maxWidth: number): ReadonlyArray<string> => {
  const { line, remaining } = splitAtWord(text, maxWidth)

  return text.length <= maxWidth ? [text] : [line, ...wrapText(remaining, maxWidth)]
}

const calculateWidths = (rows: ReadonlyArray<TableRow>, terminalWidth?: number): ColumnWidths => {
  const id = Math.max(MIN_ID_WIDTH, ...rows.map((r) => r.id.length))
  const severity = Math.max(8, ...rows.map((r) => r.severity.length))
  const module_ = Math.min(MAX_MODULE_WIDTH, Math.max(7, ...rows.map((r) => r.module.length)))
  const fix = Math.max(3, ...rows.map((r) => r.fix.length))

  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- columns is undefined in non-TTY environments
  const width = terminalWidth ?? process.stdout.columns ?? DEFAULT_TERMINAL_WIDTH
  const fixedWidth =
    id + severity + module_ + fix + URL_ESTIMATED_WIDTH + GAP_WIDTH * FIXED_COLUMN_COUNT
  const remaining = Math.max(0, width - fixedWidth)

  const naturalTitle = Math.max(MIN_TITLE_WIDTH, ...rows.map((r) => r.title.length))
  const naturalPaths = Math.min(
    MAX_PATHS_WIDTH,
    Math.max(MIN_PATHS_WIDTH, ...rows.map((r) => r.paths.length)),
  )

  const totalFlexNeeded = naturalTitle + naturalPaths
  const titleShare = totalFlexNeeded > 0 ? naturalTitle / totalFlexNeeded : 0.6
  const title = Math.max(
    MIN_TITLE_WIDTH,
    Math.min(naturalTitle, Math.floor(remaining * titleShare)),
  )
  const paths = Math.max(MIN_PATHS_WIDTH, Math.min(naturalPaths, remaining - title))

  return { id, severity, module: module_, title, paths, fix }
}

const renderHeader = (widths: ColumnWidths): string => {
  const headers = [
    padRight('ID', widths.id),
    padRight('Severity', widths.severity),
    padRight('Package', widths.module),
    padRight('Title', widths.title),
    padRight('Paths', widths.paths),
    padRight('Fix', widths.fix),
    'URL',
  ].join(COLUMN_GAP)

  const separator = [
    '─'.repeat(widths.id),
    '─'.repeat(widths.severity),
    '─'.repeat(widths.module),
    '─'.repeat(widths.title),
    '─'.repeat(widths.paths),
    '─'.repeat(widths.fix),
    '───',
  ].join(COLUMN_GAP)

  return `${headers}\n${separator}`
}

const renderRow = (row: TableRow, widths: ColumnWidths): string => {
  const titleLines = wrapText(row.title, widths.title)
  const pathLines = wrapText(row.paths, widths.paths)
  const lineCount = Math.max(titleLines.length, pathLines.length)
  const emptyPad = (width: number): string => padRight('', width)

  const firstLine = [
    padRight(row.id, widths.id),
    SEVERITY_COLORIZERS[row.severity](padRight(row.severity, widths.severity)),
    padRight(truncate(row.module, widths.module), widths.module),
    padRight(titleLines[0] ?? '', widths.title),
    padRight(truncate(pathLines[0] ?? '', widths.paths), widths.paths),
    padRight(row.fix, widths.fix),
    row.url,
  ].join(COLUMN_GAP)

  const continuationLines = Array.from({ length: lineCount - 1 }, (_, i) => {
    const lineIndex = i + 1

    return [
      emptyPad(widths.id),
      emptyPad(widths.severity),
      emptyPad(widths.module),
      padRight(titleLines[lineIndex] ?? '', widths.title),
      padRight(pathLines[lineIndex] ?? '', widths.paths),
      emptyPad(widths.fix),
      '',
    ].join(COLUMN_GAP)
  })

  return [firstLine, ...continuationLines].join('\n')
}

const colorSeverityCount = (severity: Severity, count: number): string =>
  SEVERITY_COLORIZERS[severity](`${String(count)} ${severity}`)

const countUniquePackages = (vulns: ReadonlyArray<Vulnerability>): number =>
  new Set(vulns.map((v) => v.name)).size

const countAdvisories = (vulns: ReadonlyArray<Vulnerability>): number =>
  vulns.reduce((sum, v) => sum + Math.max(1, deduplicateAdvisories(v.advisories).length), 0)

const definedStrings = (values: ReadonlyArray<string | undefined>): ReadonlyArray<string> => [
  ...new Set(values.filter((value): value is string => value !== undefined)),
]

const formatMatchedExceptions = (result: ScanResult): string => {
  const ids = definedStrings(result.exceptions.matched.map((exception) => exception.id))
  const modules = definedStrings(result.exceptions.matched.map((exception) => exception.module))
  const idsText = ids.length > 0 ? `IDs ${ids.join(', ')}` : ''
  const modulesText = modules.length > 0 ? `packages ${modules.join(', ')}` : ''
  const matchedValues = [idsText, modulesText].filter(Boolean).join(' and ')

  return matchedValues === '' ? '' : `Exceptions were added for ${matchedValues}.`
}

const wrapIfPresent = (text: string, prefix: string, suffix = ''): string =>
  text === '' ? '' : `${prefix}${text}${suffix}`

const exceptionWarning = (items: ReadonlyArray<unknown>, label: string): string =>
  items.length > 0
    ? `\n${pc.yellow(`${String(items.length)} ${label} exception(s) in config`)}`
    : ''

const formatSummary = (result: ScanResult): string => {
  const pkgCount = countUniquePackages(result.unhandled)
  const vulnCount = countAdvisories(result.unhandled)
  const total = `Found ${String(pkgCount)} package${pkgCount === 1 ? '' : 's'} with ${String(vulnCount)} vulnerabilit${vulnCount === 1 ? 'y' : 'ies'}`
  const unhandledSuffix =
    result.unhandled.length > 0 ? ` (${String(result.unhandled.length)} unhandled)` : ''
  const matchedSuffix =
    result.exceptions.matched.length > 0
      ? `, ${String(result.exceptions.matched.length)} excepted`
      : ''

  const severityBreakdown = SEVERITY_ORDER.map((s) => ({
    s,
    count: result.unhandled.filter((v) => v.severity === s).length,
  }))
    .filter(({ count }) => count > 0)
    .map(({ s, count }) => colorSeverityCount(s, count))
    .join(', ')

  const unusedWarning = exceptionWarning(result.exceptions.unused, 'unused')
  const expiredWarning = exceptionWarning(result.exceptions.expired, 'expired')
  const matchedExceptionsLine = wrapIfPresent(formatMatchedExceptions(result), '\n\n')

  return `${total}${unhandledSuffix}${matchedSuffix}\n  ${severityBreakdown}${matchedExceptionsLine}${unusedWarning}${expiredWarning}`
}

const formatTableOutput = (
  rows: ReadonlyArray<TableRow>,
  result: ScanResult,
  terminalWidth?: number,
): string => {
  const widths = calculateWidths(rows, terminalWidth)
  const header = renderHeader(widths)
  const body = rows.map((row) => renderRow(row, widths)).join('\n')
  const summary = formatSummary(result)

  return `\n${header}\n${body}\n\n${summary}\n`
}

export const formatTable = (
  result: ScanResult,
  filterSeverity: Severity | undefined,
  terminalWidth?: number,
): string => {
  const sorted = sortBySeverity(result.unhandled)
  const allRows = sorted.flatMap(vulnToRows)
  const rows = filterRows(allRows, filterSeverity)

  const emptyMessage =
    filterSeverity !== undefined && allRows.length > 0
      ? `No vulnerabilities at or above ${filterSeverity} severity.`
      : 'No vulnerabilities found.'
  const matchedExceptionsLine = wrapIfPresent(formatMatchedExceptions(result), '\n', '\n')

  return rows.length === 0
    ? `\n${pc.green(emptyMessage)}\n${matchedExceptionsLine}`
    : formatTableOutput(rows, result, terminalWidth)
}
