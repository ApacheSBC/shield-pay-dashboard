import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'
import { validateRequest, zIdParam } from '../middleware/validateRequest.js'

export const transactionsRouter = Router()
transactionsRouter.use(requireAuth)

transactionsRouter.get('/', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const rows = getDb()
      .prepare(
        `SELECT t.*, c.name AS customer_name,
                cards.pan_encrypted AS card_pan_enc, cards.cvv_encrypted AS card_cvv_enc
         FROM transactions t
         LEFT JOIN customers c ON c.id = t.customer_id
         LEFT JOIN cards ON cards.id = t.card_id
         WHERE t.merchant_id = ?
         ORDER BY t.created_at DESC
         LIMIT 200`,
      )
      .all(req.user.id)
    res.json({ transactions: rows.map((r) => transactionRowToApiMasked(r)) })
  } catch (e) {
    next(e)
  }
})

transactionsRouter.get('/:id', validateRequest({ params: zIdParam }), (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const row = getDb()
      .prepare(
        `SELECT t.*, c.name AS customer_name,
                cards.pan_encrypted AS card_pan_enc, cards.cvv_encrypted AS card_cvv_enc
         FROM transactions t
         LEFT JOIN customers c ON c.id = t.customer_id
         LEFT JOIN cards ON cards.id = t.card_id
         WHERE t.id = ? AND t.merchant_id = ?`,
      )
      .get(req.params.id, req.user.id)
    if (!row) return res.status(404).json({ error: 'Not found' })
    res.json({ transaction: transactionRowToApiMasked(row) })
  } catch (e) {
    next(e)
  }
})
