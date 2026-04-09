import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'

const MAX_CUSTOMER_SEARCH_LEN = 256

/** Escape % and _ so user input cannot broaden a LIKE pattern; backslashes doubled for ESCAPE '\\'. */
function escapeLikeLiteral(fragment) {
  return fragment
    .replace(/\\/g, '\\\\')
    .replace(/%/g, '\\%')
    .replace(/_/g, '\\_')
}

export const customersRouter = Router()
customersRouter.use(requireAuth)

customersRouter.get('/', (req, res, next) => {
  try {
    const merchantId = req.user.id
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const rawSearch = (req.query.search || '').trim()
    if (rawSearch.length > MAX_CUSTOMER_SEARCH_LEN) {
      return res.status(400).json({
        error: `search must be at most ${MAX_CUSTOMER_SEARCH_LEN} characters`,
      })
    }
    let rows
    if (rawSearch) {
      // Parameterized LIKE — user data only in bound values, never in SQL text (no SQL injection).
      const pattern = `%${escapeLikeLiteral(rawSearch)}%`
      rows = getDb()
        .prepare(
          `SELECT * FROM customers WHERE merchant_id = ? AND (name LIKE ? ESCAPE char(92) OR email LIKE ? ESCAPE char(92)) ORDER BY created_at DESC`,
        )
        .all(merchantId, pattern, pattern)
    } else {
      rows = getDb()
        .prepare('SELECT * FROM customers WHERE merchant_id = ? ORDER BY created_at DESC')
        .all(merchantId)
    }
    res.json({ customers: rows })
  } catch (e) {
    next(e)
  }
})

customersRouter.post('/', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { name, email, phone, notes } = req.body
    if (!name) return res.status(400).json({ error: 'name required' })
    const r = getDb()
      .prepare(
        `INSERT INTO customers (merchant_id, name, email, phone, notes) VALUES (?, ?, ?, ?, ?)`,
      )
      .run(req.user.id, name, email || null, phone || null, notes || null)
    const row = getDb().prepare('SELECT * FROM customers WHERE id = ?').get(r.lastInsertRowid)
    res.status(201).json({ customer: row })
  } catch (e) {
    next(e)
  }
})

customersRouter.get('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const row = getDb()
      .prepare('SELECT * FROM customers WHERE id = ? AND merchant_id = ?')
      .get(req.params.id, req.user.id)
    if (!row) return res.status(404).json({ error: 'Not found' })
    res.json({ customer: row })
  } catch (e) {
    next(e)
  }
})

// Enforce ownership: merchant can only update customers they own.
customersRouter.put('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { name, email, phone, notes } = req.body
    const existing = getDb()
      .prepare('SELECT * FROM customers WHERE id = ? AND merchant_id = ?')
      .get(req.params.id, req.user.id)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    getDb()
      .prepare(
        `UPDATE customers SET name = COALESCE(?, name), email = COALESCE(?, email), phone = COALESCE(?, phone), notes = COALESCE(?, notes) WHERE id = ?`,
      )
      .run(name ?? existing.name, email ?? existing.email, phone ?? existing.phone, notes ?? existing.notes, req.params.id)
    const row = getDb()
      .prepare('SELECT * FROM customers WHERE id = ? AND merchant_id = ?')
      .get(req.params.id, req.user.id)
    res.json({ customer: row })
  } catch (e) {
    next(e)
  }
})

// Enforce ownership: merchant can only delete customers they own.
customersRouter.delete('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const existing = getDb()
      .prepare('SELECT id FROM customers WHERE id = ? AND merchant_id = ?')
      .get(req.params.id, req.user.id)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    getDb().prepare('DELETE FROM customers WHERE id = ? AND merchant_id = ?').run(req.params.id, req.user.id)
    res.json({ ok: true })
  } catch (e) {
    next(e)
  }
})
