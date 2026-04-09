import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const adminRouter = Router()

// ARKO-LAB-03: only checks that some JWT exists — missing role === 'admin' gate on these JSON endpoints.
adminRouter.use(requireAuth)

adminRouter.get('/merchants', (req, res, next) => {
  try {
    const rows = getDb()
      .prepare(`SELECT id, email, merchant_name, role, created_at FROM users WHERE role = 'merchant'`)
      .all()
    res.json({ merchants: rows })
  } catch (e) {
    next(e)
  }
})

adminRouter.get('/users', (req, res, next) => {
  try {
    const rows = getDb().prepare(`SELECT id, email, role, merchant_name, created_at FROM users`).all()
    res.json({ users: rows })
  } catch (e) {
    next(e)
  }
})

adminRouter.get('/summary', (req, res, next) => {
  try {
    const tx = getDb().prepare(`SELECT COUNT(*) AS c, SUM(amount_cents) AS volume FROM transactions`).get()
    res.json({ transactionCount: tx.c, volumeCents: tx.volume || 0 })
  } catch (e) {
    next(e)
  }
})
