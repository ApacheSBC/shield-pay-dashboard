import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import client from '../api/client.js'

function last7DaysKeys() {
  const out = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date()
    d.setUTCDate(d.getUTCDate() - i)
    out.push(d.toISOString().slice(0, 10))
  }
  return out
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    client
      .get('/stats/dashboard')
      .then((r) => setData(r.data))
      .catch(() => setErr('Could not load dashboard'))
  }, [])

  if (err) return <p className="error-msg">{err}</p>
  if (!data) return <p style={{ color: 'var(--muted)' }}>Loading…</p>

  const keys = last7DaysKeys()
  const map = Object.fromEntries((data.last7Days || []).map((x) => [x.d, x]))
  const maxVol = Math.max(1, ...keys.map((k) => map[k]?.volume || 0))

  return (
    <>
      <h1>Dashboard</h1>
      <div className="grid grid-4">
        <div className="card stat">
          <div className="stat-value">{data.totals.transactionCount}</div>
          <div className="stat-label">Transactions</div>
        </div>
        <div className="card stat">
          <div className="stat-value">${(data.totals.volumeCents / 100).toFixed(2)}</div>
          <div className="stat-label">Captured volume</div>
        </div>
        <div className="card stat">
          <div className="stat-value">{data.totals.customerCount}</div>
          <div className="stat-label">Customers</div>
        </div>
        <div className="card stat">
          <div className="stat-value">{data.totals.cardCount}</div>
          <div className="stat-label">Saved cards</div>
        </div>
      </div>

      <div className="card">
        <h2>Last 7 days (volume)</h2>
        <div className="chart-row">
          {keys.map((k) => {
            const v = map[k]?.volume || 0
            const h = Math.round((v / maxVol) * 100)
            return (
              <div key={k} className="chart-bar-wrap">
                <div className="chart-bar" style={{ height: `${Math.max(h, 4)}%` }} title={`$${(v / 100).toFixed(2)}`} />
                <span className="chart-label">{k.slice(5)}</span>
              </div>
            )
          })}
        </div>
      </div>

      <div className="card">
        <h2>Recent transactions</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Customer</th>
                <th>Amount</th>
                <th>Status</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {data.recentTransactions.map((t) => (
                <tr key={t.id}>
                  <td>
                    <Link to={`/transactions/${t.id}`}>{t.id}</Link>
                  </td>
                  <td>{t.customer_name || '—'}</td>
                  <td>${(t.amount_cents / 100).toFixed(2)}</td>
                  <td>
                    <span className="pill">{t.status}</span>
                  </td>
                  <td className="mono">{t.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Link to="/transactions">View all</Link>
      </div>
    </>
  )
}
