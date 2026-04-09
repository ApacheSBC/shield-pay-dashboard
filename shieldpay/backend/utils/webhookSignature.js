import crypto from 'crypto'

const WEBHOOK_TOLERANCE_SECONDS = 5 * 60

function getInboundWebhookSecret() {
  const secret = String(process.env.INBOUND_WEBHOOK_SECRET || '').trim()
  if (!secret) {
    throw new Error('INBOUND_WEBHOOK_SECRET is required for inbound webhook verification')
  }
  if (secret.length < 24) {
    throw new Error('INBOUND_WEBHOOK_SECRET must be at least 24 characters')
  }
  return secret
}

function parseSignatureHeader(value) {
  const raw = String(value || '').trim()
  if (!raw) return null
  const normalized = raw.startsWith('sha256=') ? raw.slice(7) : raw
  return /^[a-fA-F0-9]{64}$/.test(normalized) ? normalized.toLowerCase() : null
}

export function verifyInboundWebhookSignature({ rawBody, timestampHeader, signatureHeader }) {
  const ts = Number.parseInt(String(timestampHeader || ''), 10)
  if (!Number.isFinite(ts)) return { ok: false, reason: 'invalid_timestamp' }
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - ts) > WEBHOOK_TOLERANCE_SECONDS) {
    return { ok: false, reason: 'timestamp_out_of_window' }
  }

  const providedHex = parseSignatureHeader(signatureHeader)
  if (!providedHex) return { ok: false, reason: 'invalid_signature_header' }

  const secret = getInboundWebhookSecret()
  const payload = `${ts}.${Buffer.from(rawBody).toString('utf8')}`
  const expectedHex = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex')

  const provided = Buffer.from(providedHex, 'hex')
  const expected = Buffer.from(expectedHex, 'hex')
  if (provided.length !== expected.length) return { ok: false, reason: 'signature_mismatch' }
  const ok = crypto.timingSafeEqual(provided, expected)
  return ok ? { ok: true } : { ok: false, reason: 'signature_mismatch' }
}
