import { type ExceptionEntry, type MatchedExceptionEntry, type Vulnerability } from './types.js'

type ExceptionResult = Readonly<{
  matched: ReadonlyArray<MatchedExceptionEntry>
  unused: ReadonlyArray<ExceptionEntry>
  expired: ReadonlyArray<ExceptionEntry>
  unhandled: ReadonlyArray<Vulnerability>
}>

const isExpired = (entry: ExceptionEntry, now: Date = new Date()): boolean =>
  entry.expiry !== undefined && new Date(entry.expiry) <= now

const isEffective = (entry: ExceptionEntry, now: Date = new Date()): boolean =>
  entry.active !== false && !isExpired(entry, now)

const matchesById = (id: string, vuln: Vulnerability): boolean =>
  vuln.advisories.some((advisory) => advisory.url.includes(id) || String(advisory.source) === id)

const matchesVulnerability = (exception: ExceptionEntry, vuln: Vulnerability): boolean =>
  (exception.module !== undefined && exception.module === vuln.name) ||
  (exception.id !== undefined && matchesById(exception.id, vuln))

export const applyExceptions = (
  vulnerabilities: ReadonlyArray<Vulnerability>,
  exceptions: ReadonlyArray<ExceptionEntry>,
  now: Date = new Date(),
): ExceptionResult => {
  const expired = exceptions.filter((e) => isExpired(e, now))
  const effective = exceptions.filter((e) => isEffective(e, now))

  const matchResults = vulnerabilities.map((vuln) => ({
    vuln,
    matches: effective.filter((exc) => matchesVulnerability(exc, vuln)),
  }))

  const unhandled = matchResults.filter((r) => r.matches.length === 0).map((r) => r.vuln)

  const matched: ReadonlyArray<MatchedExceptionEntry> = matchResults.flatMap((r) =>
    r.matches.map((exc) => ({ ...exc, matchedVulnerability: r.vuln.name })),
  )

  const usedExceptions = new Set(matchResults.flatMap((r) => r.matches))
  const unused = effective.filter((e) => !usedExceptions.has(e))

  return { matched, unused, expired, unhandled }
}
