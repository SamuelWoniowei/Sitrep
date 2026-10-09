import { describe, expect, it } from 'vitest'
import { briefScript, pcmToFloat, pickLocalVoice } from '../listen'
import type { Story } from '../api'

describe('listen mode', () => {
  it('reads headline, tldr and why for each story', () => {
    const s = { headline: 'H', tldr: 'T.', why: 'W' } as Story
    const parts = briefScript([s, s])
    expect(parts).toHaveLength(4)
    expect(parts[1]).toContain('Story 1. H. T. Why it matters: W')
  })

  it('never picks an online/cloud voice', () => {
    const voices = [
      { name: 'Microsoft Sonia Online (Natural) - English (United Kingdom)', lang: 'en-GB', localService: false },
      { name: 'Microsoft Ryan Online (Natural)', lang: 'en-GB', localService: true },
      { name: 'Microsoft George', lang: 'en-GB', localService: true },
      { name: 'Microsoft David', lang: 'en-US', localService: true },
    ]
    expect(pickLocalVoice(voices)?.name).toBe('Microsoft George')
    expect(pickLocalVoice(voices.slice(0, 2))).toBeNull()
    expect(pickLocalVoice(voices.slice(3))?.name).toBe('Microsoft David')
  })

  it('converts 16-bit PCM to floats', () => {
    const b = new ArrayBuffer(6)
    const v = new DataView(b)
    v.setInt16(0, 0, true)
    v.setInt16(2, 16384, true)
    v.setInt16(4, -32768, true)
    const f = pcmToFloat(b)
    expect(Array.from(f)).toEqual([0, 0.5, -1])
  })
})
