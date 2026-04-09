import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import client from '../api/client.js'

export default function Customers() {
  const [search, setSearch] = useState('')
  const [list, setList] = useState([])
  const [err, setErr] = useState('')

  const load = () => {
    const params = search ? { search } : {}
    client
      .get('/customers', { params })
      .then((r) => setList(r.data.customers))
      .catch(() => setErr('Failed to load customers'))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <>
      <h1>Customers</h1>
      <div className="card" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ flex: '1 1 200px', marginBottom: 0 }}>
          <label htmlFor="q">Search</label>
          <input id="q" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Name or email" />
        </div>
        <button type="button" className="btn btn-primary" onClick={load}>
          Search
        </button>
      </div>
      {err && <p className="error-msg">{err}</p>}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Phone</th>
            </tr>
          </thead>
          <tbody>
            {list.map((c) => (
              <tr key={c.id}>
                <td>
                  <Link to={`/customers/${c.id}`}>{c.name}</Link>
                </td>
                <td>{c.email || '—'}</td>
                <td>{c.phone || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
