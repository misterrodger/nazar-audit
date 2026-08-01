import { getBanner } from './banner.js'

const identity = (s: string): string => s

const noopColors = { blue: identity, cyan: identity, white: identity, bold: identity, dim: identity } as const

const fakeAnsi = (s: string): string => `\u001b[34m${s}\u001b[0m`

const ansiColors = { blue: fakeAnsi, cyan: fakeAnsi, white: fakeAnsi, bold: fakeAnsi, dim: fakeAnsi } as const

const hasAnsi = (text: string): boolean => text.includes('\u001b[')

describe('getBanner', () => {
  it('returns a non-empty multiline string', () => {
    const banner = getBanner(noopColors)

    expect(banner.length).toBeGreaterThan(0)
    expect(banner).toContain('\n')
  })

  it('is at least 10 lines tall', () => {
    const { length } = getBanner(noopColors).split('\n')

    expect(length).toBeGreaterThanOrEqual(10)
  })

  it('contains the nazar eye art characters', () => {
    const banner = getBanner(noopColors)

    expect(banner).toContain('██')
    expect(banner).toContain('░░')
    expect(banner).toContain('▓▓')
  })

  it('contains nazar-audit text and version', () => {
    const banner = getBanner(noopColors)

    expect(banner).toContain('nazar-audit')
  })

  it('applies color functions to art characters', () => {
    const banner = getBanner(ansiColors)

    expect(hasAnsi(banner)).toBe(true)
  })

  it('contains no ANSI codes when given identity color functions', () => {
    const banner = getBanner(noopColors)

    expect(hasAnsi(banner)).toBe(false)
  })

  it('produces identical line count with and without colors', () => {
    const { length: coloredLines } = getBanner(ansiColors).split('\n')
    const { length: plainLines } = getBanner(noopColors).split('\n')

    expect(coloredLines).toBe(plainLines)
  })
})
