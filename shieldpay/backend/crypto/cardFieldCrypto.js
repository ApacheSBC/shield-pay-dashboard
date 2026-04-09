import crypto from 'crypto'

const ALGO = 'aes-256-gcm'
const IV_LEN = 12
const TAG_LEN = 16
const KEY_LEN = 32

let cachedKey = null

function getKeyBuffer() {
  if (cachedKey) return cachedKey
  const b64 = (process.env.CARD_ENCRYPTION_KEY || '').trim()
  if (!b64) {
    throw new Error(
      'CARD_ENCRYPTION_KEY is required and must be a base64-encoded 32-byte key (openssl rand -base64 32).',
    )
  }
  const k = Buffer.from(b64, 'base64')
  if (k.length !== KEY_LEN) {
    throw new Error('CARD_ENCRYPTION_KEY must be base64 encoding of exactly 32 bytes')
  }
  cachedKey = k
  return cachedKey
}

/** Encrypt UTF-8 string for storage (PAN, CVV, snapshots). */
export function encryptField(plainText) {
  const key = getKeyBuffer()
  const iv = crypto.randomBytes(IV_LEN)
  const cipher = crypto.createCipheriv(ALGO, key, iv)
  const enc = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, enc]).toString('base64')
}

export function decryptField(b64) {
  if (b64 == null || b64 === '') return ''
  const buf = Buffer.from(String(b64), 'base64')
  if (buf.length < IV_LEN + TAG_LEN + 1) {
    throw new Error('Invalid ciphertext')
  }
  const iv = buf.subarray(0, IV_LEN)
  const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN)
  const data = buf.subarray(IV_LEN + TAG_LEN)
  const key = getKeyBuffer()
  const dec = crypto.createDecipheriv(ALGO, key, iv)
  dec.setAuthTag(tag)
  return Buffer.concat([dec.update(data), dec.final()]).toString('utf8')
}

export function normalizePan(pan) {
  return String(pan).replace(/\D/g, '')
}

export function normalizeCvv(cvv) {
  return String(cvv).replace(/\D/g, '')
}

/** Test/demo PANs: 13–19 digits (ISO-style range). */
export function validatePan(pan) {
  const s = normalizePan(pan)
  if (!/^\d{13,19}$/.test(s)) {
    throw new Error('PAN must be 13–19 digits')
  }
  return s
}

export function validateCvv(cvv) {
  const s = normalizeCvv(cvv)
  if (!/^\d{3,4}$/.test(s)) {
    throw new Error('CVV must be 3 or 4 digits')
  }
  return s
}

const MAX_CARD_LABEL_LEN = 120
const MAX_BRAND_LEN = 40

export function validateExpMonth(value, fallback = 12) {
  if (value === undefined || value === null || value === '') return fallback
  const n = Number(value)
  if (!Number.isInteger(n) || n < 1 || n > 12) {
    throw new Error('expMonth must be 1–12')
  }
  return n
}

export function validateExpYear(value) {
  const minY = new Date().getUTCFullYear()
  const maxY = minY + 25
  if (value === undefined || value === null || value === '') {
    return Math.min(minY + 8, maxY)
  }
  const n = Number(value)
  if (!Number.isInteger(n) || n < minY || n > maxY) {
    throw new Error(`expYear must be between ${minY} and ${maxY}`)
  }
  return n
}

export function sanitizeCardLabel(label) {
  const s = String(label ?? '').trim()
  if (s.length > MAX_CARD_LABEL_LEN) {
    throw new Error(`label must be at most ${MAX_CARD_LABEL_LEN} characters`)
  }
  return s
}

/** Short brand string for storage (alphanumeric, spaces, common punctuation). */
export function sanitizeBrand(brand) {
  const raw = String(brand ?? 'unknown').trim().slice(0, MAX_BRAND_LEN)
  if (raw.length === 0) return 'unknown'
  if (!/^[\w\s\-+.]+$/i.test(raw)) {
    throw new Error('brand contains invalid characters')
  }
  return raw
}

/** DB row → API shape with decrypted pan_plain / cvv_plain; omits ciphertext columns. Server-side only. */
export function cardRowToApi(row) {
  if (!row) return null
  const { pan_encrypted, cvv_encrypted, ...rest } = row
  let pan_plain = ''
  let cvv_plain = ''
  if (pan_encrypted != null && pan_encrypted !== '') {
    try {
      pan_plain = decryptField(pan_encrypted)
      cvv_plain = decryptField(cvv_encrypted)
    } catch {
      pan_plain = ''
      cvv_plain = ''
    }
  }
  return { ...rest, pan_plain, cvv_plain }
}

export function panLast4(panDigits) {
  const d = normalizePan(panDigits)
  if (d.length < 4) return ''
  return d.slice(-4)
}

/** PAN display: all but last four digits replaced with * (no full PAN in JSON). */
export function panMaskedDisplay(panDigits) {
  const d = normalizePan(panDigits)
  if (d.length < 4) return '****'
  const last4 = d.slice(-4)
  const stars = d.length > 4 ? '*'.repeat(d.length - 4) : ''
  return `${stars}${last4}`
}

/**
 * Public card JSON: no full PAN/CVV. Use last4 + primaryAccountNumberMasked for UI.
 */
export function cardRowToApiMasked(row) {
  const full = cardRowToApi(row)
  if (!full) return null
  const { pan_plain, cvv_plain, ...rest } = full
  return {
    ...rest,
    last4: panLast4(pan_plain) || null,
    primaryAccountNumberMasked: pan_plain ? panMaskedDisplay(pan_plain) : null,
    cardVerificationValue: null,
  }
}

/**
 * Transaction row from list/detail query (t.* + optional card_* enc + customer_name).
 * Produces pan_snapshot_plain, pan_plain, cvv_plain for clients; strips ciphertext fields.
 */
export function transactionRowToApi(row) {
  if (!row) return null
  const out = { ...row }
  const cardPanEnc = out.card_pan_enc
  const cardCvvEnc = out.card_cvv_enc
  delete out.card_pan_enc
  delete out.card_cvv_enc

  if (cardPanEnc) {
    try {
      out.pan_plain = decryptField(cardPanEnc)
      out.cvv_plain = decryptField(cardCvvEnc)
    } catch {
      out.pan_plain = ''
      out.cvv_plain = ''
    }
  } else {
    out.pan_plain = out.pan_plain ?? null
    out.cvv_plain = out.cvv_plain ?? null
  }

  const snapEnc = out.pan_snapshot_encrypted
  delete out.pan_snapshot_encrypted
  if (snapEnc) {
    try {
      out.pan_snapshot_plain = decryptField(snapEnc)
    } catch {
      out.pan_snapshot_plain = ''
    }
  } else if (out.pan_snapshot_plain != null && out.pan_snapshot_plain !== '') {
    /* legacy row if DROP COLUMN failed */
  } else {
    out.pan_snapshot_plain = null
  }

  return out
}

/**
 * Transaction JSON for clients: no full PAN/CVV or raw snapshot; masked fields only.
 */
export function transactionRowToApiMasked(row) {
  const full = transactionRowToApi(row)
  if (!full) return null
  const { pan_plain, cvv_plain, pan_snapshot_plain, ...rest } = full
  const snap = pan_snapshot_plain || ''
  const cardPan = pan_plain || ''
  const primary = cardPan || snap
  return {
    ...rest,
    last4: panLast4(primary) || null,
    panMasked: primary ? panMaskedDisplay(primary) : null,
    pan_snapshot_masked: snap ? panMaskedDisplay(snap) : null,
  }
}
