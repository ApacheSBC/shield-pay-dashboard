import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const statsRouter = Router()
statsRouter.use(requireAuth)

statsRouter.get('/dashboard', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const mid = req.user.id
    const totals = getDb()
      .prepare(
        `SELECT
           COUNT(*) AS tx_count,
           COALESCE(SUM(CASE WHEN status = 'captured' THEN amount_cents ELSE 0 END), 0) AS volume_cents
         FROM transactions WHERE merchant_id = ?`,
      )
      .get(mid)

    const customerCount = getDb()
      .prepare('SELECT COUNT(*) AS c FROM customers WHERE merchant_id = ?')
      .get(mid).c

    const cardCount = getDb().prepare('SELECT COUNT(*) AS c FROM cards WHERE merchant_id = ?').get(mid).c

    const last7 = getDb()
      .prepare(
        `SELECT date(created_at) AS d,
                COUNT(*) AS c,
                COALESCE(SUM(amount_cents), 0) AS volume
         FROM transactions
         WHERE merchant_id = ? AND created_at >= datetime('now', '-7 days')
         GROUP BY date(created_at)
         ORDER BY d ASC`,
      )
      .all(mid)

    const recent = getDb()
      .prepare(
        `SELECT t.id, t.amount_cents, t.status, t.description, t.created_at, c.name AS customer_name
         FROM transactions t
         LEFT JOIN customers c ON c.id = t.customer_id
         WHERE t.merchant_id = ?
         ORDER BY t.created_at DESC
         LIMIT 8`,
      )
      .all(mid)

    res.json({
      totals: {
        transactionCount: totals.tx_count,
        volumeCents: totals.volume_cents,
        customerCount,
        cardCount,
      },
      last7Days: last7,
      recentTransactions: recent,
    })
  } catch (e) {
    next(e)
  }
})
