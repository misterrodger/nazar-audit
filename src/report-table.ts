import pc from 'picocolors'
import {
  type Advisory,
  type ScanResult,
  type Vulnerability,
  type Severity,
  type FixAvailability,
  SEVERITY_ORDER,
} from './types.js'

type TableRow = Readonly<{
  severity: Severity
  module: string
  title: string
  fix: string
  url: string
}>

type ColumnWidths = Readonly<{
  severity: number
  module: number
  title: number
  fix: number
}>

const COLUMN_GAP = '  '
const [GAP_WIDTH] = [COLUMN_GAP.length] as const
const MIN_TITLE_WIDTH = 30
const MAX_MODULE_WIDTH = 30
const DEFAULT_TERMINAL_WIDTH = 160
const URL_ESTIMATED_WIDTH = 60

const SEVERITY_DESC = ['critical', 'high', 'moderate', 'low', 'info'] as const

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

const deduplicateAdvisories = (advisories: ReadonlyArray<Advisory>): ReadonlyArray<Advisory> =>
  advisories.filter(
    (advisory, index, all) => all.findIndex((a) => a.url === advisory.url) === index,
  )

const vulnToRows = (vuln: Vulnerability): ReadonlyArray<TableRow> => {
  const unique = deduplicateAdvisories(vuln.advisories)

  return unique.length > 0
    ? unique.map((advisory) => ({
        severity: advisory.severity,
        module: vuln.name,
        title: advisory.title,
        fix: formatFixAvailability(vuln.fixAvailable),
        url: advisory.url,
      }))
    : [
        {
          severity: vuln.severity,
          module: vuln.name,
          title: `via ${vuln.via.filter((v): v is string => typeof v === 'string').join(', ')}`,
          fix: formatFixAvailability(vuln.fixAvailable),
          url: '',
        },
      ]
}

const severityIndex = (severity: Severity): number => SEVERITY_ORDER.indexOf(severity)

const sortBySeverity = (vulns: ReadonlyArray<Vulnerability>): ReadonlyArray<Vulnerability> =>
  SEVERITY_DESC.flatMap((severity) => vulns.filter((v) => v.severity === severity))

const filterVulnerabilities = (
  vulns: ReadonlyArray<Vulnerability>,
  minSeverity: Severity | undefined,
): ReadonlyArray<Vulnerability> =>
  minSeverity === undefined
    ? vulns
    : vulns.filter((v) => severityIndex(v.severity) >= severityIndex(minSeverity))

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

const getTerminalWidth = (stdout: Readonly<{ columns?: number }> = process.stdout): number =>
  stdout.columns ?? DEFAULT_TERMINAL_WIDTH

const calculateWidths = (rows: ReadonlyArray<TableRow>): ColumnWidths => {
  const severity = Math.max(8, ...rows.map((r) => r.severity.length))
  const module_ = Math.min(MAX_MODULE_WIDTH, Math.max(6, ...rows.map((r) => r.module.length)))
  const fix = Math.max(3, ...rows.map((r) => r.fix.length))

  const fixedWidth = severity + module_ + fix + URL_ESTIMATED_WIDTH + GAP_WIDTH * 4
  const naturalTitle = Math.max(MIN_TITLE_WIDTH, ...rows.map((r) => r.title.length))
  const availableTitle = Math.max(MIN_TITLE_WIDTH, getTerminalWidth() - fixedWidth)

  return { severity, module: module_, title: Math.min(naturalTitle, availableTitle), fix }
}

const renderHeader = (widths: ColumnWidths): string => {
  const headers = [
    padRight('Severity', widths.severity),
    padRight('Package', widths.module),
    padRight('Title', widths.title),
    padRight('Fix', widths.fix),
    'URL',
  ].join(COLUMN_GAP)

  const separator = [
    '─'.repeat(widths.severity),
    '─'.repeat(widths.module),
    '─'.repeat(widths.title),
    '─'.repeat(widths.fix),
    '───',
  ].join(COLUMN_GAP)

  return `${headers}\n${separator}`
}

const renderRow = (row: TableRow, widths: ColumnWidths): string => {
  const titleLines = wrapText(row.title, widths.title)
  const emptyPad = (width: number): string => padRight('', width)

  const firstLine = [
    SEVERITY_COLORIZERS[row.severity](padRight(row.severity, widths.severity)),
    padRight(truncate(row.module, widths.module), widths.module),
    padRight(titleLines[0] ?? '', widths.title),
    padRight(row.fix, widths.fix),
    row.url,
  ].join(COLUMN_GAP)

  const continuationLines = titleLines
    .slice(1)
    .map((line) =>
      [
        emptyPad(widths.severity),
        emptyPad(widths.module),
        padRight(line, widths.title),
        emptyPad(widths.fix),
        '',
      ].join(COLUMN_GAP),
    )

  return [firstLine, ...continuationLines].join('\n')
}

const colorSeverityCount = (severity: Severity, count: number): string =>
  SEVERITY_COLORIZERS[severity](`${String(count)} ${severity}`)

const countUniquePackages = (vulns: ReadonlyArray<Vulnerability>): number =>
  new Set(vulns.map((v) => v.name)).size

const formatSummary = (result: ScanResult): string => {
  const pkgCount = countUniquePackages(result.unhandled)
  const total = `Found ${String(pkgCount)} package${pkgCount === 1 ? '' : 's'} with vulnerabilities`
  const unhandledSuffix =
    result.unhandled.length > 0 ? ` (${String(result.unhandled.length)} unhandled)` : ''
  const matchedSuffix =
    result.exceptions.matched.length > 0
      ? `, ${String(result.exceptions.matched.length)} excepted`
      : ''

  const severityBreakdown = SEVERITY_ORDER.filter((s) => result.metadata.severityCounts[s] > 0)
    .map((s) => colorSeverityCount(s, result.metadata.severityCounts[s]))
    .join(', ')

  const unusedWarning =
    result.exceptions.unused.length > 0
      ? `\n${pc.yellow(`${String(result.exceptions.unused.length)} unused exception(s) in config`)}`
      : ''

  const expiredWarning =
    result.exceptions.expired.length > 0
      ? `\n${pc.yellow(`${String(result.exceptions.expired.length)} expired exception(s) in config`)}`
      : ''

  return `${total}${unhandledSuffix}${matchedSuffix}\n  ${severityBreakdown}${unusedWarning}${expiredWarning}`
}

const formatTableOutput = (rows: ReadonlyArray<TableRow>, result: ScanResult): string => {
  const widths = calculateWidths(rows)
  const header = renderHeader(widths)
  const body = rows.map((row) => renderRow(row, widths)).join('\n')
  const summary = formatSummary(result)

  return `\n${header}\n${body}\n\n${summary}\n`
}

export const formatTable = (result: ScanResult, filterSeverity: Severity | undefined): string => {
  const sorted = sortBySeverity(filterVulnerabilities(result.unhandled, filterSeverity))
  const rows = sorted.flatMap(vulnToRows)

  return rows.length === 0
    ? `\n${pc.green('No vulnerabilities found.')}\n`
    : formatTableOutput(rows, result)
}
