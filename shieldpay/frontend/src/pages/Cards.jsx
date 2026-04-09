import React, { useEffect, useState, useCallback } from 'react'
import client from '../api/client.js'

export default function Cards() {
  const [cards, setCards] = useState([])
  const [err, setErr] = useState('')
  const [detail, setDetail] = useState(null)

  const load = useCallback(() => {
    client
      .get('/cards')
      .then((r) => setCards(r.data.cards))
      .catch(() => setErr('Failed to load cards'))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  async function showCard(cardId) {
    try {
      const { data } = await client.get(`/cards/${cardId}`)
      setDetail(data.card)
    } catch {
      setDetail({ error: 'Could not load card' })
    }
  }

  return (
    <>
      <h1>Saved cards</h1>
      <p style={{ color: 'var(--muted)', maxWidth: '640px' }}>
        API responses use masked PAN and never return CVV (last four digits only for identification).
      </p>
      {err && <p className="error-msg">{err}</p>}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>Label</th>
              <th>Customer</th>
              <th>Last 4</th>
              <th>Brand</th>
              <th>Expires</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {cards.map((c) => (
              <tr key={c.id}>
                <td>{c.label}</td>
                <td>{c.customer_name}</td>
                <td className="mono">{c.last4 || '—'}</td>
                <td>{c.brand}</td>
                <td>
                  {c.exp_month}/{c.exp_year}
                </td>
                <td>
                  <button type="button" className="btn btn-ghost" onClick={() => showCard(c.id)}>
                    View masked detail
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {detail && (
        <div className="card mono" style={{ marginTop: '1rem' }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(detail, null, 2)}</pre>
        </div>
      )}
    </>
  )
}
