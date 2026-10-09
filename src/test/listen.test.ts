import { describe, expect, it } from 'vitest'
import { briefScript } from '../listen'
import type { Story } from '../api'

describe('listen mode', () => {
  it('reads headline, tldr and why for each story', () => {
    const s = { headline: 'H', tldr: 'T.', why: 'W' } as Story
    const parts = briefScript([s, s])
    expect(parts).toHaveLength(4)
    expect(parts[1]).toContain('Story 1. H. T. Why it matters: W')
  })
})
