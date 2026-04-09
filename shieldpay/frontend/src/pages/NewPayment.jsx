import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import client from '../api/client.js'
import { safeErrorMessage } from '../utils/safeErrorMessage.js'
import { safeDisplayText } from '../utils/safeDisplayText.js'

export default function NewPayment() {
  const [cards, setCards] = useState([])
  const [cardId, setCardId] = useState('')
  const [amount, setAmount] = useState('10')
  const [description, setDescription] = useState('')
  const [result, setResult] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    client.get('/cards').then((r) => {
      setCards(r.data.cards)
      if (r.data.cards[0]) setCardId(String(r.data.cards[0].id))
    })
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    setResult(null)
    try {
      const { data } = await client.post('/payments/process', {
        cardId: Number(cardId),
        amountDollars: Number(amount),
        description,
      })
      setResult(data)
    } catch (ex) {
      setErr(safeErrorMessage(ex.response?.data?.error, 'Payment failed'))
    }
  }

  return (
    <>
      <h1>New payment</h1>
      <p style={{ color: 'var(--muted)' }}>Fake money — test card data only.</p>
      <div className="card" style={{ maxWidth: '480px' }}>
        <form onSubmit={submit}>
          <div className="form-group">
            <label htmlFor="card">Card</label>
            <select id="card" value={cardId} onChange={(e) => setCardId(e.target.value)}>
              {cards.map((c) => (
                <option key={c.id} value={c.id}>
                  {safeDisplayText(c.label, '—')} — {safeDisplayText(c.customer_name, '—')}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="amt">Amount (USD)</label>
            <input id="amt" type="number" step="0.01" min="0.01" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </div>
          <div className="form-group">
            <label htmlFor="desc">Description</label>
            <input id="desc" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          {err && <p className="error-msg">{err}</p>}
          <button type="submit" className="btn btn-primary">
            Process
          </button>
        </form>
      </div>
      {result && (
        <div className="card mono" style={{ marginTop: '1rem' }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
      <p style={{ marginTop: '1rem' }}>
        <Link to="/transactions">View transactions</Link>
      </p>
    </>
  )
}
