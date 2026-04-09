import { Router } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import net from 'net'
import { z } from 'zod'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { cardRowToApiMasked, transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'
import { validateRequest } from '../middleware/validateRequest.js'

const PRIVATE_HOST_RE = /^(localhost|localhost\.localdomain|.*\.local)$/i
const MAX_LABEL_LEN = 80
const MAX_MERCHANT_NAME_LEN = 120
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

function normalizeHost(hostname) {
  const raw = String(hostname || '').trim().toLowerCase()
  if (!raw) return ''
  return raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw
}

function ipv4ToInt(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = (out << 8) | n
  }
  return out >>> 0
}

function isPrivateOrReservedIpv4(ip) {
  const value = ipv4ToInt(ip)
  if (value == null) return false

  const inRange = (base, maskBits) => {
    const shift = 32 - maskBits
    return (value >>> shift) === (base >>> shift)
  }

  return (
    inRange(0x00000000, 8) || // 0.0.0.0/8 (software + unspecified)
    inRange(0x0a000000, 8) || // 10.0.0.0/8
    inRange(0x64400000, 10) || // 100.64.0.0/10 (CGNAT)
    inRange(0x7f000000, 8) || // 127.0.0.0/8
    inRange(0xa9fe0000, 16) || // 169.254.0.0/16
    inRange(0xac100000, 12) || // 172.16.0.0/12
    inRange(0xc0a80000, 16) || // 192.168.0.0/16
    inRange(0xc6120000, 15) || // 198.18.0.0/15 (benchmarking)
    inRange(0xe0000000, 4) // 224.0.0.0/4 (multicast + reserved)
  )
}

function parseIpv6ToBigInt(ipv6Input) {
  let ip = String(ipv6Input || '').toLowerCase()
  if (!ip) return null

  // Handle IPv4-mapped tail (e.g., ::ffff:192.168.1.10).
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':')
    if (lastColon <= -1) return null
    const v4 = ip.slice(lastColon + 1)
    const v4Int = ipv4ToInt(v4)
    if (v4Int == null) return null
    const hi = ((v4Int >>> 16) & 0xffff).toString(16)
    const lo = (v4Int & 0xffff).toString(16)
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`
  }

  const doubleColonCount = ip.split('::').length - 1
  if (doubleColonCount > 1) return null

  let groups = []
  if (ip.includes('::')) {
    const [left, right] = ip.split('::')
    const leftGroups = left ? left.split(':') : []
    const rightGroups = right ? right.split(':') : []
    const fill = 8 - (leftGroups.length + rightGroups.length)
    if (fill < 0) return null
    groups = [...leftGroups, ...Array(fill).fill('0'), ...rightGroups]
  } else {
    groups = ip.split(':')
    if (groups.length !== 8) return null
  }

  if (groups.length !== 8) return null

  let out = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
    out = (out << 16n) + BigInt(`0x${g}`)
  }
  return out
}

function isPrivateOrReservedIpv6(ip) {
  const value = parseIpv6ToBigInt(ip)
  if (value == null) return false

  const inRange = (baseHex, prefixBits) => {
    const base = BigInt(baseHex)
    const shift = 128n - BigInt(prefixBits)
    return (value >> shift) === (base >> shift)
  }

  // ::/128 unspecified, ::1/128 loopback, fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast.
  if (value === 0n || value === 1n) return true
  if (inRange('0xfc000000000000000000000000000000', 7)) return true
  if (inRange('0xfe800000000000000000000000000000', 10)) return true
  if (inRange('0xff000000000000000000000000000000', 8)) return true

  // IPv4-mapped IPv6 range ::ffff:0:0/96; evaluate mapped IPv4 for private/reserved blocks.
  if (inRange('0x00000000000000000000ffff00000000', 96)) {
    const mappedV4 = Number(value & 0xffffffffn)
    const v4 =
      `${(mappedV4 >>> 24) & 0xff}.${(mappedV4 >>> 16) & 0xff}.` +
      `${(mappedV4 >>> 8) & 0xff}.${mappedV4 & 0xff}`
    return isPrivateOrReservedIpv4(v4)
  }

  return false
}

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
  const hostname = normalizeHost(parsed.hostname)
  if (!hostname) return null
  if (PRIVATE_HOST_RE.test(hostname)) return null

  const ipVersion = net.isIP(hostname)
  if (ipVersion === 4 && isPrivateOrReservedIpv4(hostname)) return null
  if (ipVersion === 6 && isPrivateOrReservedIpv6(hostname)) return null

  // Keep webhook targets focused on origin paths; fragments are unnecessary.
  parsed.hash = ''
  return parsed.toString()
}

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

settingsRouter.post('/webhooks', validateRequest({ body: webhookCreateBodySchema }), (req, res, next) => {
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
