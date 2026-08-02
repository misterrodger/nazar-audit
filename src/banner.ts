import pc from 'picocolors'
import { APP_NAME, VERSION } from './constants.js'

const NAZAR_ART = [
  '         ██████████████',
  '      ███░░░░░░░░░░░░░░███',
  '    ██░░░░░░▓▓▓▓▓▓▓▓░░░░░░██',
  '   ██░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░██',
  '  ██░░░▓▓▓▓██████████▓▓▓▓░░░██',
  '  ██░░░▓▓▓▓██████████▓▓▓▓░░░██',
  '   ██░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░██',
  '    ██░░░░░░▓▓▓▓▓▓▓▓░░░░░░██',
  '      ███░░░░░░░░░░░░░░███',
  '         ██████████████',
] as const

type ColorFn = (s: string) => string

const colorizeChar = (ch: string, blue: ColorFn, cyan: ColorFn, white: ColorFn): string =>
  ch === '█' ? blue('█') : ch === '░' ? white('░') : ch === '▓' ? cyan('▓') : ch

const colorizeLine = (line: string, blue: ColorFn, cyan: ColorFn, white: ColorFn): string =>
  // eslint-disable-next-line @typescript-eslint/no-misused-spread -- art uses only BMP Unicode, no multi-byte surrogates
  [...line].map((ch) => colorizeChar(ch, blue, cyan, white)).join('')

export const getBanner = (
  colors: Readonly<{
    blue: ColorFn
    cyan: ColorFn
    white: ColorFn
    bold: ColorFn
    dim: ColorFn
  }> = pc,
): string => {
  const brightWhite = (s: string): string => colors.bold(colors.white(s))
  const art = NAZAR_ART.map((line) =>
    colorizeLine(line, colors.blue, colors.cyan, brightWhite),
  ).join('\n')
  const text = `  ${colors.bold(colors.cyan(APP_NAME))}${colors.dim(` v${VERSION}`)}`

  return `${art}\n${text}`
}
