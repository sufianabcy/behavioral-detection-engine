/**
 * App.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Root component — fetches alert data from the FastAPI backend and orchestrates
 * the three dashboard panels.
 *
 * States handled
 * ──────────────
 *   loading   → skeleton/spinner overlay
 *   error     → friendly error card with retry button
 *   empty     → empty-state guidance card
 *   data      → SummaryMetrics + MitreBarChart + AlertsTable
 *
 * Data shape expected from GET http://localhost:8000/alerts
 * ──────────────────────────────────────────────────────────
 *   { total: number, alerts: AlertOut[] }
 *
 * AlertOut fields used
 * ─────────────────────
 *   id, alert_id, triggered_at, host, cumulative_score, threshold,
 *   window_seconds, window_start, window_end,
 *   mitre_techniques: string[], families: string[],
 *   reason, contributing_rules: ContributingRule[]
 */

import { useState, useEffect, useCallback } from 'react'
import SummaryMetrics from './components/SummaryMetrics'
import MitreBarChart  from './components/MitreBarChart'
import AlertsTable    from './components/AlertsTable'

const API_BASE = 'http://localhost:8000'
const POLL_MS  = 30_000   // auto-refresh every 30 s

// ── Loading skeleton ──────────────────────────────────────────────────────────
function Skeleton({ className = '' }) {
  return <div className={`animate-pulse rounded-lg bg-surface-border ${className}`} />
}

function LoadingState() {
  return (
    <div className="space-y-8">
      {/* Metrics row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-32" />)}
      </div>
      {/* Chart */}
      <Skeleton className="h-64" />
      {/* Table */}
      <Skeleton className="h-80" />
    </div>
  )
}

// ── Error card ────────────────────────────────────────────────────────────────
function ErrorCard({ error, onRetry }) {
  const isCORS    = error.message?.includes('Failed to fetch') || error.message?.includes('NetworkError')
  const isTimeout = error.message?.includes('timeout')

  return (
    <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-8 flex flex-col items-center gap-4 text-center">
      <span className="text-5xl">⚠️</span>

      <div>
        <p className="text-lg font-semibold text-red-300 mb-1">
          {isCORS ? 'Cannot reach the API server' : 'Failed to load alerts'}
        </p>
        <p className="text-sm text-slate-400 max-w-md">
          {isCORS
            ? 'Make sure the FastAPI backend is running on port 8000.'
            : isTimeout
              ? 'The request timed out. The server may be overloaded.'
              : error.message}
        </p>
      </div>

      {isCORS && (
        <pre className="text-xs bg-surface-card border border-surface-border rounded-lg px-4 py-3 text-slate-400 text-left w-full max-w-md overflow-x-auto">
{`cd behavioral-detection-engine
uvicorn backend.main:app --reload --port 8000`}
        </pre>
      )}

      <button
        onClick={onRetry}
        className="
          mt-2 px-5 py-2 rounded-lg bg-red-500/20 border border-red-500/30
          text-red-300 text-sm font-medium
          hover:bg-red-500/30 transition-colors
        "
      >
        Retry
      </button>
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-card p-10 flex flex-col items-center gap-4 text-center">
      <span className="text-5xl">🛡️</span>
      <div>
        <p className="text-lg font-semibold text-slate-300 mb-1">No alerts yet</p>
        <p className="text-sm text-slate-500 max-w-md">
          Send events to the backend to start seeing detection results.
        </p>
      </div>
      <pre className="text-xs bg-surface border border-surface-border rounded-lg px-4 py-3 text-slate-400 text-left max-w-lg overflow-x-auto">
{`# Generate 100 mixed events and push them to the backend
cd behavioral-detection-engine
python3 simulator/run_all.py --total 100 --malicious-ratio 0.4 --no-file \\
  | python3 - << 'EOF'
import sys, json, urllib.request, urllib.error
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    data = json.dumps(json.loads(line)).encode()
    req  = urllib.request.Request(
        "http://localhost:8000/events",
        data=data, headers={"Content-Type":"application/json"})
    try: urllib.request.urlopen(req)
    except: pass
print("Done")
EOF`}
      </pre>
    </div>
  )
}

// ── Header ────────────────────────────────────────────────────────────────────
function Header({ lastUpdated, loading, onRefresh }) {
  return (
    <header className="flex items-center justify-between mb-8 flex-wrap gap-4">
      <div className="flex items-center gap-3">
        {/* Shield icon */}
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/30 to-teal-500/10 border border-emerald-500/30 flex items-center justify-center">
          <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>

        <div>
          <h1 className="text-lg font-bold text-slate-100 leading-tight">
            Behavioural Detection Engine
          </h1>
          <p className="text-xs text-slate-500">SOC Alert Dashboard</p>
        </div>
      </div>

      {/* Status + refresh */}
      <div className="flex items-center gap-3">
        {lastUpdated && (
          <p className="text-xs text-slate-600">
            Updated {lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </p>
        )}

        {/* Live indicator */}
        <div className="flex items-center gap-1.5 text-xs text-emerald-500">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          LIVE
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          title="Refresh data"
          className="
            p-2 rounded-lg border border-surface-border
            text-slate-400 hover:text-slate-200 hover:border-slate-500
            disabled:opacity-40 disabled:cursor-not-allowed
            transition-colors
          "
        >
          <svg
            className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
          </svg>
        </button>
      </div>
    </header>
  )
}

// ── Stats bar ─────────────────────────────────────────────────────────────────
function StatsBar({ total, apiBase }) {
  return (
    <div className="flex items-center gap-2 text-xs text-slate-600 mb-6">
      <span className="font-mono bg-surface-card border border-surface-border px-2 py-0.5 rounded text-slate-500">
        GET {apiBase}/alerts
      </span>
      <span>→</span>
      <span className="text-slate-500">{total} alert{total !== 1 ? 's' : ''} returned</span>
    </div>
  )
}

// ── Root App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [alerts,      setAlerts]      = useState([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchAlerts = useCallback(async (signal) => {
    setLoading(true)
    setError(null)

    try {
      const res = await fetch(`${API_BASE}/alerts?limit=1000`, {
        signal,
        headers: { Accept: 'application/json' },
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail ?? `HTTP ${res.status} ${res.statusText}`)
      }

      const data = await res.json()
      setAlerts(data.alerts ?? [])
      setLastUpdated(new Date())
    } catch (err) {
      if (err.name === 'AbortError') return   // component unmounted
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial load + auto-refresh every 30 s
  useEffect(() => {
    const controller = new AbortController()
    fetchAlerts(controller.signal)

    const timer = setInterval(() => fetchAlerts(controller.signal), POLL_MS)
    return () => {
      controller.abort()
      clearInterval(timer)
    }
  }, [fetchAlerts])

  const handleRefresh = () => fetchAlerts(new AbortController().signal)

  return (
    <div className="min-h-screen bg-surface text-slate-100">
      {/* Subtle top accent line */}
      <div className="h-0.5 bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Header lastUpdated={lastUpdated} loading={loading} onRefresh={handleRefresh} />

        {/* Content */}
        {error ? (
          <ErrorCard error={error} onRetry={handleRefresh} />
        ) : loading && alerts.length === 0 ? (
          <LoadingState />
        ) : (
          <>
            <StatsBar total={alerts.length} apiBase={API_BASE} />

            {alerts.length === 0 ? (
              <EmptyState />
            ) : (
              <div className="space-y-10">
                <SummaryMetrics alerts={alerts} />
                <MitreBarChart  alerts={alerts} />
                <AlertsTable    alerts={alerts} />
              </div>
            )}
          </>
        )}
      </div>

      {/* Footer */}
      <footer className="text-center text-xs text-slate-700 py-6 mt-8 border-t border-surface-border">
        Behavioural Detection Engine · Phase 4 Dashboard · API&nbsp;
        <a href={`${API_BASE}/docs`} target="_blank" rel="noreferrer" className="hover:text-slate-500 underline underline-offset-2">
          {API_BASE}/docs
        </a>
      </footer>
    </div>
  )
}

