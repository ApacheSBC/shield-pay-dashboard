import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import client from '../api/client.js'
import { safeDisplayText } from '../utils/safeDisplayText.js'

export default function TransactionDetail() {
  const { id } = useParams()
  const [tx, setTx] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    client
      .get(`/transactions/${id}`)
      .then((r) => setTx(r.data.transaction))
      .catch(() => setErr('Not found'))
  }, [id])

  if (err) return <p className="error-msg">{err}</p>
  if (!tx) return <p style={{ color: 'var(--muted)' }}>Loading…</p>

  return (
    <>
      <p>
        <Link to="/transactions">← Transactions</Link>
      </p>
      <h1>Transaction #{tx.id}</h1>
      <div className="card">
        <p>
          <strong>Amount:</strong> ${(tx.amount_cents / 100).toFixed(2)} {tx.currency}
        </p>
        <p>
          <strong>Status:</strong> <span className="pill">{safeDisplayText(tx.status, '—')}</span>
        </p>
        <p>
          <strong>Customer:</strong> {safeDisplayText(tx.customer_name, '—')}
        </p>
        <p>
          <strong>Description:</strong> {safeDisplayText(tx.description, '—')}
        </p>
        <p>
          <strong>PAN snapshot (masked):</strong>{' '}
          <span className="mono">{tx.pan_snapshot_masked || '—'}</span>
        </p>
        <p>
          <strong>Payment method:</strong>{' '}
          <span className="mono">
            {tx.panMasked || '—'} (CVV never returned by API)
          </span>
        </p>
        <p>
          <strong>Last 4:</strong> <span className="mono">{tx.last4 || '—'}</span>
        </p>
        <p className="mono" style={{ color: 'var(--muted)' }}>
          {tx.created_at}
        </p>
      </div>
    </>
  )
}
