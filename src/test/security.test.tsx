import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Story } from '../api'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))
const { StoryCard } = await import('../StoryCard')

const evil = '<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>'

const story: Story = {
  id: '0123456789abcdef01234567',
  category: 'exploited_now',
  category_label: 'EXPLOITED NOW',
  sources: ['Test'],
  published: Math.floor(Date.now() / 1000),
  original_title: evil,
  headline: evil,
  tldr: evil,
  why: evil,
  deeper: evil,
  gist: evil,
  plain: evil,
  action: evil,
  roles: [{ role: evil, note: evil }],
  cvss: [{ cve: evil, score: 9.8, severity: evil, exploited: true }],
  terms: [{ term: evil, plain: evil }],
  cves: [],
  watch_hits: [],
  ai: true,
  read: false,
  has_link: true,
}

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? files(p) : [p]
  })
}

describe('UI renders untrusted text safely', () => {
  it('never turns feed or AI text into HTML', () => {
    const { container } = render(
      <StoryCard story={story} index={0} open deeper aiReady onOpen={() => {}} onRead={() => {}} />,
    )
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined()
    // The payload is visible as inert text instead.
    expect(screen.getAllByText(evil, { exact: false }).length).toBeGreaterThan(0)
  })
})

describe('source code guardrails', () => {
  const src = files(join(__dirname, '..')).filter((f) => /\.(tsx?|jsx?)$/.test(f) && !f.includes('/test/'))
  const banned: [RegExp, string][] = [
    [/dangerouslySetInnerHTML/, 'raw HTML rendering'],
    [/\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML/, 'DOM HTML injection'],
    [/\beval\s*\(|new Function\s*\(/, 'dynamic code execution'],
    [/\bfetch\s*\(|XMLHttpRequest|WebSocket\s*\(/, 'network access from the UI'],
    [/localStorage|sessionStorage/, 'unencrypted browser storage'],
  ]
  for (const [re, why] of banned) {
    it(`does not use ${why}`, () => {
      const hits = src.filter((f) => re.test(readFileSync(f, 'utf8')))
      expect(hits).toEqual([])
    })
  }
})
