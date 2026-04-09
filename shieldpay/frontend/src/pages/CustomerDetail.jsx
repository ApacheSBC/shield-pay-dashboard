import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import client from '../api/client.js'
import { safeDisplayText } from '../utils/safeDisplayText.js'

export default function CustomerDetail() {
  const { id } = useParams()
  const [customer, setCustomer] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    client
      .get(`/customers/${id}`)
      .then((r) => setCustomer(r.data.customer))
      .catch(() => setErr('Not found or no access'))
  }, [id])

  if (err) return <p className="error-msg">{err}</p>
  if (!customer) return <p style={{ color: 'var(--muted)' }}>Loading…</p>

  return (
    <>
      <p>
        <Link to="/customers">← Customers</Link>
      </p>
      <h1>{safeDisplayText(customer.name, 'Customer')}</h1>
      <div className="card">
        <p>
          <strong>Email:</strong> {safeDisplayText(customer.email, '—')}
        </p>
        <p>
          <strong>Phone:</strong> {safeDisplayText(customer.phone, '—')}
        </p>
        <p>
          <strong>Notes:</strong> {safeDisplayText(customer.notes, '—')}
        </p>
        <p className="mono" style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>
          Created {customer.created_at}
        </p>
      </div>
      <Link to="/cards">View cards</Link>
    </>
  )
}
