/**
 * MitreBarChart.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Horizontal bar chart showing the frequency of each MITRE ATT&CK technique
 * across all alerts.  Techniques are sorted by frequency (descending).
 *
 * Props
 * ─────
 *   alerts  list[AlertOut]   — array fetched from GET /alerts
 */

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LabelList,
} from 'recharts'

// ── Aggregate technique counts ────────────────────────────────────────────────
function buildChartData(alerts) {
  const counts = {}
  alerts.forEach(alert => {
    alert.mitre_techniques.forEach(tech => {
      counts[tech] = (counts[tech] || 0) + 1
    })
  })
  return Object.entries(counts)
    .map(([technique, count]) => ({ technique, count }))
    .sort((a, b) => b.count - a.count)
}

// ── Colour scale by rank (most frequent = most vivid) ────────────────────────
const BAR_COLOURS = [
  '#f87171', // red-400
  '#fb923c', // orange-400
  '#facc15', // yellow-400
  '#4ade80', // green-400
  '#34d399', // emerald-400
  '#22d3ee', // cyan-400
  '#60a5fa', // blue-400
  '#a78bfa', // violet-400
  '#f472b6', // pink-400
  '#94a3b8', // slate-400
]
const barColour = (index) => BAR_COLOURS[index % BAR_COLOURS.length]

// ── Custom tooltip ────────────────────────────────────────────────────────────
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg px-3 py-2 shadow-xl text-sm">
      <p className="font-mono font-semibold text-slate-200">{label}</p>
      <p className="text-slate-400 mt-0.5">
        Triggered in{' '}
        <span className="text-emerald-400 font-semibold">{payload[0].value}</span>{' '}
        alert{payload[0].value !== 1 ? 's' : ''}
      </p>
    </div>
  )
}

// ── Custom Y-axis tick ────────────────────────────────────────────────────────
function TechTick({ x, y, payload }) {
  return (
    <text
      x={x - 4}
      y={y}
      textAnchor="end"
      dominantBaseline="middle"
      fill="#94a3b8"
      fontSize={12}
      fontFamily="JetBrains Mono, monospace"
    >
      {payload.value}
    </text>
  )
}

export default function MitreBarChart({ alerts }) {
  const data = buildChartData(alerts)

  if (data.length === 0) {
    return (
      <section>
        <ChartHeader />
        <div className="rounded-xl border border-surface-border bg-surface-card p-8 flex flex-col items-center justify-center text-slate-500 gap-2">
          <span className="text-3xl">📡</span>
          <p className="text-sm">No technique data yet — ingest some events.</p>
        </div>
      </section>
    )
  }

  // Dynamic height: at least 280px, 40px per bar
  const chartHeight = Math.max(280, data.length * 42)

  return (
    <section>
      <ChartHeader count={data.length} />
      <div className="rounded-xl border border-surface-border bg-surface-card p-6 overflow-x-auto">
        <ResponsiveContainer width="100%" height={chartHeight}>
          <BarChart
            layout="vertical"
            data={data}
            margin={{ top: 4, right: 56, left: 110, bottom: 4 }}
            barCategoryGap="28%"
          >
            <CartesianGrid
              horizontal={false}
              strokeDasharray="3 3"
              stroke="#1e2535"
            />
            <XAxis
              type="number"
              allowDecimals={false}
              tick={{ fill: '#64748b', fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: '#1e2535' }}
              label={{
                value: 'Alert count',
                position: 'insideBottomRight',
                offset: -4,
                fill: '#475569',
                fontSize: 11,
              }}
            />
            <YAxis
              type="category"
              dataKey="technique"
              width={110}
              tick={<TechTick />}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              content={<CustomTooltip />}
              cursor={{ fill: '#1e2535' }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={28}>
              {data.map((entry, index) => (
                <Cell key={entry.technique} fill={barColour(index)} fillOpacity={0.85} />
              ))}
              <LabelList
                dataKey="count"
                position="right"
                style={{ fill: '#94a3b8', fontSize: 12, fontFamily: 'monospace' }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

function ChartHeader({ count }) {
  return (
    <div className="flex items-baseline gap-2 mb-3">
      <h2 className="text-xs font-semibold tracking-widest text-slate-500 uppercase">
        MITRE ATT&amp;CK Technique Frequency
      </h2>
      {count !== undefined && (
        <span className="text-xs text-slate-600">({count} unique technique{count !== 1 ? 's' : ''})</span>
      )}
    </div>
  )
}

