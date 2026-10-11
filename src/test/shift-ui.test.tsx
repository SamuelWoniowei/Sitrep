// Smoke test of the ticket workflow in the page: claim, then escalate with a handover.
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(() => Promise.resolve({})) }))
import { ShiftPage } from '../Shift'

describe('ticket workflow in the page', () => {
  it('needs a claim before a disposition, and a full handover to escalate', async () => {
    render(<ShiftPage aiReady={false} />)
    fireEvent.click(screen.getByText(/Start shift at/))
    fireEvent.click((await screen.findAllByText(/TKT-\d+/))[0].closest('button')!)
    expect(screen.getByText(/Claim this ticket to assess severity/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Claim ticket TKT-/ }))
    expect(await screen.findByLabelText('Severity')).toBeTruthy()
    fireEvent.click(screen.getByRole('radio', { name: /Escalate to IR/ }))
    const btn = screen.getByRole('button', { name: 'Escalate ticket' }) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
    for (const l of ['What happened', 'Who and what is affected', 'When', 'Done and needed next']) {
      fireEvent.change(screen.getByLabelText(l), { target: { value: 'Mailbox rule forwards to an outside address' } })
    }
    expect(btn.disabled).toBe(false)
    fireEvent.click(btn)
    expect(await screen.findByText('ESCALATED')).toBeTruthy()
  })
})
