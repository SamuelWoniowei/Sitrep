// The shift catalogue. To add a shift: write shifts/sNN.ts exporting a ShiftDef,
// import it here, and add its id to SHIFT_IDS in src-tauri/src/commands.rs
// (and personas for its callable people in src-tauri/src/ai.rs).
import type { Level, ShiftDef } from './types'
import { withNoise } from './noise'
import { shift1 } from './shifts/s01'
import { noise1 } from './noise/n01'
import { shift2 } from './shifts/s02'
import { noise2 } from './noise/n02'
import { shift3 } from './shifts/s03'
import { noise3 } from './noise/n03'
import { shift4 } from './shifts/s04'
import { noise4 } from './noise/n04'
import { shift5 } from './shifts/s05'
import { noise5 } from './noise/n05'
import { shift6 } from './shifts/s06'
import { noise6 } from './noise/n06'
import { shift7 } from './shifts/s07'
import { noise7 } from './noise/n07'
import { shift8 } from './shifts/s08'
import { noise8 } from './noise/n08'
import { shift9 } from './shifts/s09'
import { noise9 } from './noise/n09'
import { shift10 } from './shifts/s10'
import { noise10 } from './noise/n10'

export const LEVELS: Level[] = ['Starter', 'Easy', 'Medium', 'Hard', 'Expert']

// Each shift's main story plus a handful of routine alerts, so the queue is
// never just the attack. The number of alerts is deliberately not shown.
const ALL: ShiftDef[] = [
  withNoise(shift1, noise1), withNoise(shift2, noise2), withNoise(shift3, noise3), withNoise(shift4, noise4), withNoise(shift5, noise5),
  withNoise(shift6, noise6), withNoise(shift7, noise7), withNoise(shift8, noise8), withNoise(shift9, noise9), withNoise(shift10, noise10),
]

// Shown easiest first; within a level, by id.
export const SHIFTS: ShiftDef[] = [...ALL].sort(
  (a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || a.id.localeCompare(b.id, undefined, { numeric: true }),
)
export const getShift = (id: string): ShiftDef | undefined => SHIFTS.find((s) => s.id === id)
