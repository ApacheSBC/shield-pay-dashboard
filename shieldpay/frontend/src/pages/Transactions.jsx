import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import client from '../api/client.js'

export default function Transactions() {
  const [rows, setRows] = useState([])
  const [err, setErr] = useState('')

  useEffect(() => {
    client
      .get('/transactions')
      .then((r) => setRows(r.data.transactions))
      .catch(() => setErr('Failed to load transactions'))
  }, [])

  return (
    <>
      <h1>Transactions</h1>
      {err && <p className="error-msg">{err}</p>}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Customer</th>
              <th>Last 4</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr key={t.id}>
                <td>
                  <Link to={`/transactions/${t.id}`}>{t.id}</Link>
                </td>
                <td>${(t.amount_cents / 100).toFixed(2)}</td>
                <td>
                  <span className="pill">{t.status}</span>
                </td>
                <td>{t.customer_name || '—'}</td>
                <td className="mono">{t.last4 || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
