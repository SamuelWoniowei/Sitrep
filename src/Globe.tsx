import { useEffect, useMemo, useRef, useState } from 'react'
import { geoGraticule10, geoInterpolate, geoOrthographic, geoPath, geoCentroid, geoDistance } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Topology, GeometryCollection } from 'topojson-specification'
import type { FeatureCollection, Geometry } from 'geojson'
import countries110 from 'world-atlas/countries-110m.json'
import { animationsOn, reducedMotion } from './prefs'

export interface GlobeNode { id: string; name: string; lat: number; lon: number; count: number }
export interface GlobeArc { actor: string; from: string; to: string; count: number }

type Fc = FeatureCollection<Geometry, { name?: string }>

function toFc(topo: unknown): Fc {
  const t = topo as Topology<{ countries: GeometryCollection<{ name?: string }> }>
  return feature(t, t.objects.countries) as unknown as Fc
}

const BASE = toFc(countries110)
const SIZE = 560

interface Props {
  nodes: GlobeNode[]
  arcs: GlobeArc[]
  selected: string | null
  onSelect: (iso: string | null) => void
}

// An interactive globe: drag to turn, scroll or +/- to zoom. Zoomed in, it
// switches to a more detailed map and names every country in view. The map data
// ships inside the app; nothing is fetched.
export function Globe({ nodes, arcs, selected, onSelect }: Props) {
  const [rot, setRot] = useState<[number, number]>([-8, -28])
  const [k, setK] = useState(1)
  const [detail, setDetail] = useState<Fc | null>(null)
  const drag = useRef<{ x: number; y: number; rot: [number, number]; id: number; moved: boolean } | null>(null)
  const svgRef = useRef<SVGSVGElement | null>(null)
  const spin = animationsOn() && !reducedMotion()

  // Load the detailed map only the first time the user zooms in.
  useEffect(() => {
    if (k > 2.2 && !detail) {
      void import('world-atlas/countries-50m.json').then((m) => setDetail(toFc(m.default)))
    }
  }, [k, detail])

  // Turn the globe to face whatever was picked, from the map or the list.
  useEffect(() => {
    const n = selected ? nodes.find((x) => x.id === selected) : null
    if (n) setRot([-n.lon, Math.max(-60, Math.min(60, -n.lat))])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected])

  // Gentle idle rotation, paused while dragging or when something is selected.
  useEffect(() => {
    if (!spin || selected) return
    let raf = 0
    let last = performance.now()
    const tick = (t: number) => {
      if (!drag.current) {
        const dt = t - last
        setRot((r) => [r[0] + dt * 0.004 / Math.max(1, k), r[1]])
      }
      last = t
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [spin, selected, k])

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      setK((v) => Math.min(8, Math.max(1, v * (e.deltaY < 0 ? 1.15 : 1 / 1.15))))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  // Packets travelling along each line, so the connections visibly move.
  const [phase, setPhase] = useState(0)
  useEffect(() => {
    if (!animationsOn() || reducedMotion()) return
    let raf = 0
    const tick = (t: number) => { setPhase((t / 3200) % 1); raf = requestAnimationFrame(tick) }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [])

  const proj = useMemo(
    () => geoOrthographic().translate([SIZE / 2, SIZE / 2]).scale((SIZE / 2 - 14) * k).rotate([rot[0], rot[1], 0]).clipAngle(90),
    [rot, k],
  )
  const path = useMemo(() => geoPath(proj), [proj])
  const data = k > 2.2 && detail ? detail : BASE
  const center: [number, number] = [-rot[0], -rot[1]]
  const visible = (lon: number, lat: number) => geoDistance([lon, lat], center) < Math.PI / 2 - 0.05
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])

  const labels = useMemo(() => {
    if (k <= 3.2) return []
    return data.features
      .map((f) => ({ name: f.properties?.name ?? '', c: geoCentroid(f) }))
      .filter((l) => l.name && visible(l.c[0], l.c[1]))
      .slice(0, 60)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, rot, k])

  // Capturing the pointer on press sends the follow-up click to the SVG instead
  // of the dot or country that was clicked, so capture only once the user has
  // really dragged. A plain click then reaches its target.
  const down = (e: React.PointerEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, rot, id: e.pointerId, moved: false }
  }
  const move = (e: React.PointerEvent) => {
    const d = drag.current
    if (!d) return
    if (!d.moved) {
      if (Math.hypot(e.clientX - d.x, e.clientY - d.y) < 4) return
      d.moved = true
      try { ;(e.currentTarget as Element).setPointerCapture(d.id) } catch { /* pointer already gone */ }
    }
    const s = 0.35 / k
    setRot([d.rot[0] + (e.clientX - d.x) * s, Math.max(-85, Math.min(85, d.rot[1] - (e.clientY - d.y) * s))])
  }
  const up = (e: React.PointerEvent) => {
    const d = drag.current
    drag.current = null
    if (d?.moved) { try { (e.currentTarget as Element).releasePointerCapture(d.id) } catch { /* already released */ } }
  }

  return (
    <div className="globe-wrap">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        className="globe"
        role="img"
        aria-label="Interactive globe of countries named in recent security news"
        onPointerDown={down}
        onPointerMove={move}
        onPointerUp={up}
        onPointerCancel={up}
      >
        <circle cx={SIZE / 2} cy={SIZE / 2} r={(SIZE / 2 - 14) * k} className="globe-sea" />
        <path d={path(geoGraticule10()) ?? ''} className="globe-grid" />
        {data.features.map((f, i) => (
          <path
            key={f.properties?.name ?? i}
            d={path(f) ?? ''}
            className={`globe-land ${byId.has(f.properties?.name ?? '') ? 'globe-hot' : ''}`}
            onClick={byId.has(f.properties?.name ?? '') ? (e) => { e.stopPropagation(); const id = f.properties?.name ?? ''; onSelect(selected === id ? null : id) } : undefined}
          />
        ))}
        {arcs.map((a) => {
          const from = nodes.find((n) => n.id === a.from)
          const to = nodes.find((n) => n.id === a.to)
          if (!from || !to) return null
          const d = path({ type: 'LineString', coordinates: [[from.lon, from.lat], [to.lon, to.lat]] })
          return d ? <path key={`${a.actor}-${a.from}-${a.to}`} d={d} className="globe-arc" /> : null
        })}
        {phase > 0 && arcs.map((a, i) => {
          const from = nodes.find((n) => n.id === a.from)
          const to = nodes.find((n) => n.id === a.to)
          if (!from || !to) return null
          const pt = geoInterpolate([from.lon, from.lat], [to.lon, to.lat])((phase + i * 0.17) % 1)
          if (!visible(pt[0], pt[1])) return null
          const xy = proj(pt)
          return xy ? <circle key={`pk-${a.actor}-${a.from}-${a.to}`} cx={xy[0]} cy={xy[1]} r={2.6} className="globe-packet" /> : null
        })}
        {labels.map((l) => {
          const p = proj(l.c)
          return p ? <text key={l.name} x={p[0]} y={p[1]} className="globe-label">{l.name}</text> : null
        })}
        {nodes.filter((n) => visible(n.lon, n.lat)).map((n) => {
          const p = proj([n.lon, n.lat])
          if (!p) return null
          const r = 4 + Math.min(8, n.count * 1.5)
          return (
            <g key={n.id} className={`globe-node ${selected === n.id ? 'globe-node-on' : ''}`} onClick={(e) => { e.stopPropagation(); onSelect(selected === n.id ? null : n.id) }}>
              <circle cx={p[0]} cy={p[1]} r={Math.max(14, r + 4)} className="globe-hit" />
              <circle cx={p[0]} cy={p[1]} r={r} className="globe-pulse" />
              <circle cx={p[0]} cy={p[1]} r={Math.max(3, r / 2)} className="globe-dot" />
              <title>{n.name}: {n.count} {n.count === 1 ? 'story' : 'stories'}</title>
            </g>
          )
        })}
      </svg>
      <div className="globe-controls">
        <button type="button" className="btn" aria-label="Zoom in" onClick={() => setK((v) => Math.min(8, v * 1.4))}>+</button>
        <button type="button" className="btn" aria-label="Zoom out" onClick={() => setK((v) => Math.max(1, v / 1.4))}>−</button>
        <button type="button" className="btn" onClick={() => { setK(1); setRot([-8, -28]); onSelect(null) }}>Reset</button>
      </div>
    </div>
  )
}
