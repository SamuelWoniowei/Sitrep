// The shift catalogue. To add a shift: write shifts/sNN.ts exporting a ShiftDef,
// import it here, and add its id to SHIFT_IDS in src-tauri/src/commands.rs
// (and personas for its callable people in src-tauri/src/ai.rs).
import type { Level, ShiftDef } from './types'
import { shift1 } from './shifts/s01'
import { shift2 } from './shifts/s02'
import { shift3 } from './shifts/s03'
import { shift4 } from './shifts/s04'
import { shift5 } from './shifts/s05'
import { shift6 } from './shifts/s06'
import { shift7 } from './shifts/s07'
import { shift8 } from './shifts/s08'
import { shift9 } from './shifts/s09'
import { shift10 } from './shifts/s10'

export const LEVELS: Level[] = ['Starter', 'Easy', 'Medium', 'Hard', 'Expert']

const ALL: ShiftDef[] = [shift1, shift2, shift3, shift4, shift5, shift6, shift7, shift8, shift9, shift10]

// Shown easiest first; within a level, by id.
export const SHIFTS: ShiftDef[] = [...ALL].sort(
  (a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || a.id.localeCompare(b.id, undefined, { numeric: true }),
)
export const getShift = (id: string): ShiftDef | undefined => SHIFTS.find((s) => s.id === id)
