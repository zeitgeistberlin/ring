import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

type ExportTarget = string | Record<string, string>

describe('published package exports', () => {
  it('only exposes files included in the package artifact', () => {
    const packageJson = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { exports: Record<string, ExportTarget> }

    for (const target of Object.values(packageJson.exports)) {
      const paths =
        typeof target === 'string' ? [target] : Object.values(target)

      expect(paths.every((path) => path.startsWith('./lib/'))).toBe(true)
    }
  })
})
