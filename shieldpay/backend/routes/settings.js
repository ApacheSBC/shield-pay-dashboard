import { Router } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { z } from 'zod'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { cardRowToApiMasked, transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'
import { validateRequest } from '../middleware/validateRequest.js'
import { normalizeAndValidateWebhookUrl, parseWebhookAllowedHosts } from '../utils/webhookDestinationSafety.js'

const MAX_LABEL_LEN = 80
const MAX_MERCHANT_NAME_LEN = 120
const webhookAllowedHosts = parseWebhookAllowedHosts()
const profilePatchBodySchema = z.object({
  merchantName: z.string().trim().min(1).max(MAX_MERCHANT_NAME_LEN).optional(),
})
const apiKeysCreateBodySchema = z.object({
  label: z.string().trim().max(MAX_LABEL_LEN).optional(),
})
const webhookCreateBodySchema = z.object({
  url: z.string().trim().url().max(2048),
  secret: z.string().trim().max(512).optional(),
})

function sanitizeLabel(input, fallback = 'API key') {
  const text = String(input ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  if (!text) return fallback
  return text.slice(0, MAX_LABEL_LEN)
}

function sanitizeMerchantName(input) {
  const text = String(input ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  return text.slice(0, MAX_MERCHANT_NAME_LEN)
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

settingsRouter.patch('/profile', validateRequest({ body: profilePatchBodySchema }), async (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { merchantName } = req.body
    if (typeof merchantName === 'string') {
      const merchantNameSafe = sanitizeMerchantName(merchantName)
      if (!merchantNameSafe) {
        return res.status(400).json({ error: 'merchantName cannot be empty' })
      }
      getDb().prepare('UPDATE users SET merchant_name = ? WHERE id = ?').run(merchantNameSafe, req.user.id)
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
    res.json({
      keys: rows.map((k) => ({
        ...k,
        label: sanitizeLabel(k.label),
      })),
    })
  } catch (e) {
    next(e)
  }
})

settingsRouter.post('/api-keys', validateRequest({ body: apiKeysCreateBodySchema }), async (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { label } = req.body
    const labelSafe = sanitizeLabel(label)
    const randomPart = crypto.randomBytes(24).toString('base64url')
    const raw = `sk_${req.user.id}_${randomPart}`
    const key_hash = await bcrypt.hash(raw, 8)
    const r = getDb()
      .prepare(
        `INSERT INTO merchant_api_keys (merchant_id, key_prefix, key_hash, label) VALUES (?, ?, ?, ?)`,
      )
      .run(req.user.id, raw.slice(0, 12), key_hash, labelSafe)
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

settingsRouter.post('/webhooks', validateRequest({ body: webhookCreateBodySchema }), async (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { url, secret } = req.body
    if (!url) return res.status(400).json({ error: 'url required' })
    const safeUrl = await normalizeAndValidateWebhookUrl(url, webhookAllowedHosts)
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
