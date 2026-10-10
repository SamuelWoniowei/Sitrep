import { describe, expect, it } from 'vitest'
import { briefScript, pcmToFloat, pickLocalVoice } from '../listen'
import type { Story } from '../api'

describe('listen mode', () => {
  it('speaks a plain-English summary, not the card text', () => {
    const s = { headline: 'Flaw (CVE-2026-102255) exploited', tldr: 'Technical tldr.', why: 'WHYTEXT', plain: 'Attackers got in through an old door.', action: 'Update the box' } as Story
    const t = { headline: 'Second', tldr: 'Plain fallback', why: 'x', plain: '', action: '' } as Story
    const parts = briefScript([s, t])
    expect(parts).toHaveLength(4)
    expect(parts[1]).toBe('First: Flaw exploited. Attackers got in through an old door. What to do: Update the box.')
    expect(parts[2]).toBe('Last: Second. Plain fallback.')
    expect(parts.join(' ')).not.toMatch(/WHYTEXT|CVE-|Why it matters/)
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
