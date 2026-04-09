import { Router } from 'express'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import {
  cardRowToApiMasked,
  encryptField,
  validatePan,
  validateCvv,
  validateExpMonth,
  validateExpYear,
  sanitizeCardLabel,
  sanitizeBrand,
} from '../crypto/cardFieldCrypto.js'

export const cardsRouter = Router()
cardsRouter.use(requireAuth)

cardsRouter.get('/', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const rows = getDb()
      .prepare(
        `SELECT c.*, cu.name AS customer_name FROM cards c
         JOIN customers cu ON cu.id = c.customer_id
         WHERE c.merchant_id = ? ORDER BY c.created_at DESC`,
      )
      .all(req.user.id)
    res.json({ cards: rows.map((r) => cardRowToApiMasked(r)) })
  } catch (e) {
    next(e)
  }
})

cardsRouter.post('/', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { customerId, pan, cvv, brand, expMonth, expYear, label } = req.body
    if (!customerId || pan == null || cvv == null) {
      return res.status(400).json({ error: 'customerId, pan, cvv required (test data only)' })
    }
    let panNorm
    let cvvNorm
    let expM
    let expY
    let labelSafe
    let brandSafe
    try {
      panNorm = validatePan(pan)
      cvvNorm = validateCvv(cvv)
      expM = validateExpMonth(expMonth)
      expY = validateExpYear(expYear)
      labelSafe = sanitizeCardLabel(label)
      brandSafe = sanitizeBrand(brand)
    } catch (err) {
      return res.status(400).json({ error: err.message })
    }
    const cust = getDb()
      .prepare('SELECT id FROM customers WHERE id = ? AND merchant_id = ?')
      .get(customerId, req.user.id)
    if (!cust) return res.status(400).json({ error: 'Invalid customer' })
    // At rest: only AES-256-GCM ciphertext in pan_encrypted / cvv_encrypted (see CARD_ENCRYPTION_KEY).
    const r = getDb()
      .prepare(
        `INSERT INTO cards (customer_id, merchant_id, pan_encrypted, cvv_encrypted, brand, exp_month, exp_year, label)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        customerId,
        req.user.id,
        encryptField(panNorm),
        encryptField(cvvNorm),
        brandSafe,
        expM,
        expY,
        labelSafe,
      )
    const row = getDb().prepare('SELECT * FROM cards WHERE id = ?').get(r.lastInsertRowid)
    res.status(201).json({ card: cardRowToApiMasked(row) })
  } catch (e) {
    next(e)
  }
})

cardsRouter.get('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const row = getDb()
      .prepare(
        `SELECT * FROM cards WHERE id = ? AND merchant_id = ?`,
      )
      .get(req.params.id, req.user.id)
    if (!row) return res.status(404).json({ error: 'Not found' })
    res.json({ card: cardRowToApiMasked(row) })
  } catch (e) {
    next(e)
  }
})

// ARKO-LAB-02: update saved card by id without verifying merchant ownership on the existing row.
cardsRouter.put('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { label, expMonth, expYear } = req.body
    const existing = getDb().prepare('SELECT * FROM cards WHERE id = ?').get(req.params.id)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    getDb()
      .prepare(
        `UPDATE cards SET label = COALESCE(?, label), exp_month = COALESCE(?, exp_month), exp_year = COALESCE(?, exp_year) WHERE id = ?`,
      )
      .run(label ?? existing.label, expMonth ?? existing.exp_month, expYear ?? existing.exp_year, req.params.id)
    const row = getDb().prepare('SELECT * FROM cards WHERE id = ?').get(req.params.id)
    res.json({ card: cardRowToApiMasked(row) })
  } catch (e) {
    next(e)
  }
})

// ARKO-LAB-02: delete card by id without JWT merchant_id match enforcement.
cardsRouter.delete('/:id', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const existing = getDb().prepare('SELECT id FROM cards WHERE id = ?').get(req.params.id)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    getDb().prepare('DELETE FROM cards WHERE id = ?').run(req.params.id)
    res.json({ ok: true })
  } catch (e) {
    next(e)
  }
})
