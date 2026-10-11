// The shift catalogue. To add a shift: write shifts/sNN.ts exporting a ShiftDef,
// import it here, and add its id to SHIFT_IDS in src-tauri/src/commands.rs
// (and personas for its callable people in src-tauri/src/ai.rs).
import type { Level, ShiftDef } from './types'
import { shift1 } from './shifts/s01'

export const LEVELS: Level[] = ['Starter', 'Easy', 'Medium', 'Hard', 'Expert']

const ALL: ShiftDef[] = [shift1]

// Shown easiest first; within a level, by id.
export const SHIFTS: ShiftDef[] = [...ALL].sort(
  (a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || a.id.localeCompare(b.id, undefined, { numeric: true }),
)
export const getShift = (id: string): ShiftDef | undefined => SHIFTS.find((s) => s.id === id)
