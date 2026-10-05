/**
 * AlertsTable.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Full-detail alerts table with:
 *   • Sortable columns (triggered_at, host, cumulative_score)
 *   • Score badges colour-coded by severity tier
 *   • MITRE technique tags
 *   • Family tags
 *   • Expandable reason row
 *   • Pagination (10 rows per page)
 *
 * Props
 * ─────
 *   alerts  list[AlertOut]   — array fetched from GET /alerts
 */

import { useState, useMemo } from 'react'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  })
}

function scoreBadge(score) {
  if (score >= 100)
    return 'bg-red-500/20 text-red-300 border border-red-500/40'
  if (score >= 60)
    return 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
  return 'bg-slate-500/20 text-slate-400 border border-slate-600/40'
}

function scoreTier(score) {
  if (score >= 100) return 'CRITICAL'
  if (score >= 60)  return 'HIGH'
  return 'MED'
}

const FAMILY_COLOURS = {
  powershell: 'bg-blue-500/20 text-blue-300',
  wmi:        'bg-purple-500/20 text-purple-300',
  certutil:   'bg-orange-500/20 text-orange-300',
  generic:    'bg-slate-500/20 text-slate-400',
}
const familyColour = (f) => FAMILY_COLOURS[f] ?? 'bg-slate-500/20 text-slate-400'

// ── Sort icon ─────────────────────────────────────────────────────────────────
function SortIcon({ active, direction }) {
  return (
    <span className={`ml-1 text-xs ${active ? 'text-slate-300' : 'text-slate-600'}`}>
      {!active ? '↕' : direction === 'asc' ? '↑' : '↓'}
    </span>
  )
}

// ── Expandable reason row ─────────────────────────────────────────────────────
function AlertRow({ alert, index }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <tr
        className="alert-row cursor-pointer transition-colors duration-100"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Index */}
        <td className="px-4 py-3 text-xs text-slate-600 tabular-nums font-mono w-10">
          {index + 1}
        </td>

        {/* Timestamp */}
        <td className="px-4 py-3 text-xs text-slate-400 font-mono whitespace-nowrap">
          {fmtTime(alert.triggered_at)}
        </td>

        {/* Host */}
        <td className="px-4 py-3">
          <span className="text-sm font-semibold text-slate-200 font-mono">
            {alert.host}
          </span>
        </td>

        {/* Score */}
        <td className="px-4 py-3">
          <span className={`inline-flex items-center gap-1.5 text-xs font-semibold font-mono px-2 py-0.5 rounded-full ${scoreBadge(alert.cumulative_score)}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${alert.cumulative_score >= 100 ? 'bg-red-400 animate-pulse' : 'bg-amber-400'}`} />
            {scoreTier(alert.cumulative_score)}&nbsp;{alert.cumulative_score}
          </span>
        </td>

        {/* Families */}
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {alert.families.map(f => (
              <span key={f} className={`text-xs px-1.5 py-0.5 rounded font-mono ${familyColour(f)}`}>
                {f}
              </span>
            ))}
          </div>
        </td>

        {/* MITRE techniques */}
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {alert.mitre_techniques.map(t => (
              <span
                key={t}
                title={t}
                className="text-xs px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono"
              >
                {t}
              </span>
            ))}
          </div>
        </td>

        {/* Top contributing rule score */}
        <td className="px-4 py-3 text-xs text-slate-500 font-mono">
          {alert.contributing_rules.length > 0
            ? `${alert.contributing_rules.length} rule${alert.contributing_rules.length !== 1 ? 's' : ''}`
            : '—'}
        </td>

        {/* Expand caret */}
        <td className="px-4 py-3 text-slate-600 text-xs">
          {expanded ? '▲' : '▼'}
        </td>
      </tr>

      {/* Expanded reason + contributing rules */}
      {expanded && (
        <tr className="bg-surface-hover">
          <td colSpan={8} className="px-6 pb-4 pt-2">
            {/* Reason */}
            <p className="text-xs text-slate-400 leading-relaxed mb-3 border-l-2 border-slate-600 pl-3">
              {alert.reason}
            </p>

            {/* Contributing rules table */}
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Contributing Rules
            </p>
            <div className="overflow-x-auto rounded-lg border border-surface-border">
              <table className="min-w-full text-xs">
                <thead>
                  <tr className="border-b border-surface-border">
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Rule ID</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Rule Name</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Score</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {alert.contributing_rules.map((r, i) => (
                    <tr key={i} className="border-b border-surface-border last:border-0">
                      <td className="px-3 py-1.5 font-mono text-emerald-400">{r.rule_id}</td>
                      <td className="px-3 py-1.5 text-slate-300">{r.rule_name}</td>
                      <td className="px-3 py-1.5 font-mono text-amber-400">+{r.score}pt</td>
                      <td className="px-3 py-1.5 font-mono text-slate-500">{fmtTime(r.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const PAGE_SIZE = 10

const SORT_COLS = ['triggered_at', 'host', 'cumulative_score']

export default function AlertsTable({ alerts }) {
  const [sortCol, setSortCol]   = useState('triggered_at')
  const [sortDir, setSortDir]   = useState('desc')
  const [page, setPage]         = useState(0)
  const [search, setSearch]     = useState('')

  // Filter by host or MITRE technique search
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return alerts
    return alerts.filter(a =>
      a.host.toLowerCase().includes(q) ||
      a.mitre_techniques.some(t => t.toLowerCase().includes(q)) ||
      a.families.some(f => f.toLowerCase().includes(q))
    )
  }, [alerts, search])

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let av = a[sortCol]
      let bv = b[sortCol]
      if (typeof av === 'string') av = av.toLowerCase()
      if (typeof bv === 'string') bv = bv.toLowerCase()
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [filtered, sortCol, sortDir])

  const totalPages  = Math.ceil(sorted.length / PAGE_SIZE)
  const paginated   = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  function handleSort(col) {
    if (sortCol === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortCol(col)
      setSortDir('desc')
    }
    setPage(0)
  }

  const thBase = 'px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider select-none'
  const thSort = `${thBase} cursor-pointer hover:text-slate-300 transition-colors`

  return (
    <section>
      {/* Header row */}
      <div className="flex items-center justify-between mb-3 gap-4">
        <h2 className="text-xs font-semibold tracking-widest text-slate-500 uppercase whitespace-nowrap">
          Alerts Detail
          <span className="ml-2 text-slate-600 normal-case font-normal tracking-normal">
            ({filtered.length} of {alerts.length})
          </span>
        </h2>

        {/* Search */}
        <div className="relative max-w-xs w-full">
          <input
            type="text"
            placeholder="Filter by host, technique, family…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            className="
              w-full bg-surface-card border border-surface-border rounded-lg
              pl-9 pr-3 py-1.5 text-sm text-slate-300 placeholder-slate-600
              focus:outline-none focus:border-slate-500 transition-colors
            "
          />
          <svg
            className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600"
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-surface-border bg-surface-card overflow-hidden">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-500 gap-2">
            <span className="text-4xl">🔍</span>
            <p className="text-sm">No alerts match your filter.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="border-b border-surface-border">
                  <tr>
                    <th className={thBase}>#</th>
                    <th className={thSort} onClick={() => handleSort('triggered_at')}>
                      Timestamp <SortIcon active={sortCol === 'triggered_at'} direction={sortDir} />
                    </th>
                    <th className={thSort} onClick={() => handleSort('host')}>
                      Host <SortIcon active={sortCol === 'host'} direction={sortDir} />
                    </th>
                    <th className={thSort} onClick={() => handleSort('cumulative_score')}>
                      Score <SortIcon active={sortCol === 'cumulative_score'} direction={sortDir} />
                    </th>
                    <th className={thBase}>Families</th>
                    <th className={thBase}>MITRE Techniques</th>
                    <th className={thBase}>Rules</th>
                    <th className={thBase}></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-border">
                  {paginated.map((alert, i) => (
                    <AlertRow
                      key={alert.alert_id}
                      alert={alert}
                      index={page * PAGE_SIZE + i}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-surface-border">
                <p className="text-xs text-slate-500">
                  Page {page + 1} of {totalPages} · {filtered.length} results
                </p>
                <div className="flex gap-1">
                  <PagBtn onClick={() => setPage(0)}         disabled={page === 0}            label="«" />
                  <PagBtn onClick={() => setPage(p => p-1)}  disabled={page === 0}            label="‹" />
                  <PagBtn onClick={() => setPage(p => p+1)}  disabled={page === totalPages-1} label="›" />
                  <PagBtn onClick={() => setPage(totalPages-1)} disabled={page === totalPages-1} label="»" />
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  )
}

function PagBtn({ onClick, disabled, label }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="
        w-7 h-7 flex items-center justify-center rounded text-xs
        text-slate-400 hover:text-slate-200 hover:bg-surface-hover
        disabled:opacity-30 disabled:cursor-not-allowed transition-colors
      "
    >
      {label}
    </button>
  )
}

