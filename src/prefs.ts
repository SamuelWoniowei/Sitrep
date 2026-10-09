// UI preferences. Stored in the app's local database via Rust (the webview
// itself never uses browser storage). Animations default to on.
import { api } from './api'

let current = true

export function animationsOn(): boolean {
  return current
}

export function applyAnimations(on: boolean): void {
  current = on
  document.documentElement.classList.toggle('anim-off', !on)
}

export async function loadAnimations(): Promise<void> {
  try {
    applyAnimations(await api.getAnimations())
  } catch {
    applyAnimations(true)
  }
}

export async function setAnimations(on: boolean): Promise<void> {
  applyAnimations(on)
  try {
    await api.setAnimations(on)
  } catch {
    /* the choice still applies for this session */
  }
}

export function reducedMotion(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}
