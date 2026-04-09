import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { cardRowToApi, encryptField, transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'

export const paymentsRouter = Router()
paymentsRouter.use(requireAuth)

paymentsRouter.post('/process', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { cardId, customerId, amountDollars, description } = req.body
    if (!cardId || amountDollars == null) {
      return res.status(400).json({ error: 'cardId and amountDollars required' })
    }
    const cardRow = getDb()
      .prepare('SELECT * FROM cards WHERE id = ? AND merchant_id = ?')
      .get(cardId, req.user.id)
    if (!cardRow) return res.status(400).json({ error: 'Invalid card' })
    const card = cardRowToApi(cardRow)
    const amount_cents = Math.round(Number(amountDollars) * 100)
    if (!Number.isFinite(amount_cents) || amount_cents <= 0) {
      return res.status(400).json({ error: 'Invalid amount' })
    }
    let custId = card.customer_id
    if (customerId != null && customerId !== '') {
      const customerRow = getDb()
        .prepare('SELECT id FROM customers WHERE id = ? AND merchant_id = ?')
        .get(customerId, req.user.id)
      if (!customerRow) {
        return res.status(400).json({ error: 'Invalid customer' })
      }
      custId = customerRow.id
    }
    const panSnap = encryptField(card.pan_plain)
    const r = getDb()
      .prepare(
        `INSERT INTO transactions (merchant_id, customer_id, card_id, amount_cents, currency, status, description, pan_snapshot_encrypted)
         VALUES (?, ?, ?, ?, 'USD', 'captured', ?, ?)`,
      )
      .run(req.user.id, custId, cardId, amount_cents, description || 'Payment', panSnap)
    const txRow = getDb().prepare('SELECT * FROM transactions WHERE id = ?').get(r.lastInsertRowid)
    const tx = transactionRowToApiMasked(txRow)
    res.status(201).json({
      transaction: tx,
    })
  } catch (e) {
    next(e)
  }
})
