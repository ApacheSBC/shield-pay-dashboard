import React, { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import client from '../api/client.js'

export default function Admin() {
  const { user } = useAuth()
  const [users, setUsers] = useState([])
  const [merchants, setMerchants] = useState([])
  const [summary, setSummary] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    if (user?.role !== 'admin') return
    Promise.all([
      client.get('/admin/users'),
      client.get('/admin/merchants'),
      client.get('/admin/summary'),
    ])
      .then(([u, m, s]) => {
        setUsers(u.data.users)
        setMerchants(m.data.merchants)
        setSummary(s.data)
      })
      .catch(() => setErr('Admin access denied or unavailable.'))
  }, [user])

  if (user?.role !== 'admin') {
    return <Navigate to="/" replace />
  }

  return (
    <>
      <h1>Admin</h1>
      <p style={{ color: 'var(--muted)', maxWidth: '720px' }}>
        Admin data is protected by server-side role-based authorization.
      </p>
      {err && <p className="error-msg">{err}</p>}
      {summary && (
        <div className="grid grid-4">
          <div className="card stat">
            <div className="stat-value">{summary.transactionCount}</div>
            <div className="stat-label">All transactions</div>
          </div>
          <div className="card stat">
            <div className="stat-value">${((summary.volumeCents || 0) / 100).toFixed(2)}</div>
            <div className="stat-label">Global volume</div>
          </div>
        </div>
      )}
      <div className="card">
        <h2>Users</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Role</th>
                <th>Merchant</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.id}</td>
                  <td>{u.email}</td>
                  <td>{u.role}</td>
                  <td>{u.merchant_name || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="card">
        <h2>Merchants</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Name</th>
              </tr>
            </thead>
            <tbody>
              {merchants.map((m) => (
                <tr key={m.id}>
                  <td>{m.id}</td>
                  <td>{m.email}</td>
                  <td>{m.merchant_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
