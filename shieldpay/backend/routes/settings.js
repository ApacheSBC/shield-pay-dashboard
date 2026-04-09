import { Router } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { cardRowToApiMasked, transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'

const PRIVATE_IPV4_RE =
  /^(127\.|10\.|0\.0\.0\.0$|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/
const PRIVATE_HOST_RE = /^(localhost|localhost\.localdomain|.*\.local)$/i
const IPV6_LOOPBACK_RE = /^(::1|0:0:0:0:0:0:0:1)$/i

function validateWebhookUrl(input) {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null
  let parsed
  try {
    parsed = new URL(trimmed)
  } catch {
    return null
  }

  if (!['https:', 'http:'].includes(parsed.protocol)) return null
  if (!parsed.hostname) return null
  if (parsed.username || parsed.password) return null
  if (PRIVATE_HOST_RE.test(parsed.hostname)) return null
  if (PRIVATE_IPV4_RE.test(parsed.hostname)) return null
  if (IPV6_LOOPBACK_RE.test(parsed.hostname)) return null
  if (parsed.hostname.includes(':') && parsed.hostname.toLowerCase().startsWith('fe80')) return null

  // Keep webhook targets focused on origin paths; fragments are unnecessary.
  parsed.hash = ''
  return parsed.toString()
}

export const settingsRouter = Router()
settingsRouter.use(requireAuth)

settingsRouter.get('/profile', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const row = getDb()
      .prepare('SELECT id, email, merchant_name, role, created_at FROM users WHERE id = ?')
      .get(req.user.id)
    res.json({ profile: row })
  } catch (e) {
    next(e)
  }
})

settingsRouter.patch('/profile', async (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { merchantName } = req.body
    if (merchantName) {
      getDb().prepare('UPDATE users SET merchant_name = ? WHERE id = ?').run(merchantName, req.user.id)
    }
    const row = getDb()
      .prepare('SELECT id, email, merchant_name, role, created_at FROM users WHERE id = ?')
      .get(req.user.id)
    res.json({ profile: row })
  } catch (e) {
    next(e)
  }
})

settingsRouter.get('/api-keys', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const rows = getDb()
      .prepare('SELECT id, key_prefix, label, created_at FROM merchant_api_keys WHERE merchant_id = ?')
      .all(req.user.id)
    res.json({ keys: rows })
  } catch (e) {
    next(e)
  }
})

settingsRouter.post('/api-keys', async (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { label } = req.body
    const randomPart = crypto.randomBytes(24).toString('base64url')
    const raw = `sk_${req.user.id}_${randomPart}`
    const key_hash = await bcrypt.hash(raw, 8)
    const r = getDb()
      .prepare(
        `INSERT INTO merchant_api_keys (merchant_id, key_prefix, key_hash, label) VALUES (?, ?, ?, ?)`,
      )
      .run(req.user.id, raw.slice(0, 12), key_hash, label || 'API key')
    res.status(201).json({ id: r.lastInsertRowid, secret: raw, message: 'Store this secret once' })
  } catch (e) {
    next(e)
  }
})

// Export decrypts card fields for merchant backup; at-rest data remains ciphertext in DB.
settingsRouter.get('/export', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const customers = getDb()
      .prepare('SELECT * FROM customers WHERE merchant_id = ?')
      .all(req.user.id)
    const cardRows = getDb()
      .prepare('SELECT * FROM cards WHERE merchant_id = ?')
      .all(req.user.id)
    const txRows = getDb()
      .prepare('SELECT * FROM transactions WHERE merchant_id = ?')
      .all(req.user.id)
    res.json({
      exportedAt: new Date().toISOString(),
      customers,
      cards: cardRows.map((r) => cardRowToApiMasked(r)),
      transactions: txRows.map((r) => transactionRowToApiMasked(r)),
    })
  } catch (e) {
    next(e)
  }
})

settingsRouter.get('/webhooks', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const rows = getDb().prepare('SELECT * FROM webhooks WHERE merchant_id = ?').all(req.user.id)
    res.json({ webhooks: rows })
  } catch (e) {
    next(e)
  }
})

settingsRouter.post('/webhooks', (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { url, secret } = req.body
    if (!url) return res.status(400).json({ error: 'url required' })
    const safeUrl = validateWebhookUrl(url)
    if (!safeUrl) {
      return res.status(400).json({ error: 'Invalid webhook URL. Use public http(s) endpoint only.' })
    }
    const r = getDb()
      .prepare(`INSERT INTO webhooks (merchant_id, url, secret, active) VALUES (?, ?, ?, 1)`)
      .run(req.user.id, safeUrl, secret || '')
    const row = getDb().prepare('SELECT * FROM webhooks WHERE id = ?').get(r.lastInsertRowid)
    res.status(201).json({ webhook: row })
  } catch (e) {
    next(e)
  }
})
