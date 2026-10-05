/**
 * SummaryMetrics.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Displays three KPI cards derived from the alerts array:
 *   • Total Alerts
 *   • High Severity   (cumulative_score 60–99)
 *   • Critical        (cumulative_score ≥ 100)
 *
 * Props
 * ─────
 *   alerts  list[AlertOut]   — array fetched from GET /alerts
 */

export default function SummaryMetrics({ alerts }) {
  const total    = alerts.length
  const high     = alerts.filter(a => a.cumulative_score >= 60 && a.cumulative_score < 100).length
  const critical = alerts.filter(a => a.cumulative_score >= 100).length

  // Unique hosts that have been alerted on
  const uniqueHosts = new Set(alerts.map(a => a.host)).size

  const cards = [
    {
      label:   'Total Alerts',
      value:   total,
      sub:     `across ${uniqueHosts} host${uniqueHosts !== 1 ? 's' : ''}`,
      color:   'from-blue-500/20 to-blue-600/5',
      border:  'border-blue-500/30',
      badge:   'bg-blue-500/20 text-blue-300',
      dot:     'bg-blue-400',
      icon: (
        <svg className="w-6 h-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
      ),
    },
    {
      label:   'High Severity',
      value:   high,
      sub:     'score 60 – 99',
      color:   'from-amber-500/20 to-amber-600/5',
      border:  'border-amber-500/30',
      badge:   'bg-amber-500/20 text-amber-300',
      dot:     'bg-amber-400',
      icon: (
        <svg className="w-6 h-6 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
        </svg>
      ),
    },
    {
      label:   'Critical',
      value:   critical,
      sub:     'score ≥ 100',
      color:   'from-red-500/20 to-red-600/5',
      border:  'border-red-500/30',
      badge:   'bg-red-500/20 text-red-300',
      dot:     'bg-red-500 animate-pulse-slow',
      icon: (
        <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
        </svg>
      ),
    },
    {
      label:   'Unique MITRE Techniques',
      value:   new Set(alerts.flatMap(a => a.mitre_techniques)).size,
      sub:     'across all alerts',
      color:   'from-emerald-500/20 to-emerald-600/5',
      border:  'border-emerald-500/30',
      badge:   'bg-emerald-500/20 text-emerald-300',
      dot:     'bg-emerald-400',
      icon: (
        <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      ),
    },
  ]

  return (
    <section>
      <h2 className="text-xs font-semibold tracking-widest text-slate-500 uppercase mb-3">
        Summary Metrics
      </h2>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card) => (
          <div
            key={card.label}
            className={`
              relative rounded-xl border ${card.border}
              bg-gradient-to-br ${card.color}
              backdrop-blur-sm p-5 overflow-hidden
              transition-transform duration-200 hover:-translate-y-0.5
            `}
          >
            {/* Icon */}
            <div className="flex items-start justify-between mb-4">
              <div className={`p-2 rounded-lg ${card.badge}`}>
                {card.icon}
              </div>
              <span className={`w-2 h-2 rounded-full mt-1 ${card.dot}`} />
            </div>

            {/* Value */}
            <p className="text-4xl font-bold text-slate-100 tabular-nums leading-none mb-1">
              {card.value}
            </p>

            {/* Label + sub */}
            <p className="text-sm font-medium text-slate-300 mt-2">{card.label}</p>
            <p className="text-xs text-slate-500 mt-0.5">{card.sub}</p>

            {/* Subtle background glow */}
            <div className="absolute -right-4 -bottom-4 w-24 h-24 rounded-full opacity-10 blur-2xl bg-current" />
          </div>
        ))}
      </div>
    </section>
  )
}

