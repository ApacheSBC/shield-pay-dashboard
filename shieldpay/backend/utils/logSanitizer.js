const MASK = '[REDACTED]'

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
const BEARER_RE = /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi
const LONG_TOKEN_RE = /\b[A-Za-z0-9_\-.=]{20,}\b/g
const CARD_RE = /\b(?:\d[ -]*?){13,19}\b/g
const CVV_RE = /\b\d{3,4}\b/g
const SECRET_KV_RE =
  /\b(password|newPassword|adminPassword|token|authorization|jwt|secret|api[_-]?key|cvv|pan|card(number)?)\b\s*[:=]\s*["']?[^"',\s}]+["']?/gi

function looksLikeCvvContext(text) {
  return /\bcvv\b/i.test(text)
}

export function sanitizeText(input) {
  const text = String(input ?? '')
  let out = text
    .replace(SECRET_KV_RE, (_, key) => `${key}=${MASK}`)
    .replace(BEARER_RE, `Bearer ${MASK}`)
    .replace(EMAIL_RE, '***EMAIL***')
    .replace(CARD_RE, '***CARD***')
    .replace(LONG_TOKEN_RE, (token) => (token.includes('.') ? MASK : token))

  // CVV regex is intentionally conservative and only applied when "cvv" context exists.
  if (looksLikeCvvContext(text)) {
    out = out.replace(CVV_RE, '***CVV***')
  }
  return out
}

export function sanitizeErrorForLog(err) {
  if (!err) return { message: 'Unknown error' }
  return {
    name: sanitizeText(err.name || 'Error'),
    message: sanitizeText(err.message || 'Unknown error'),
    stack: sanitizeText(err.stack || ''),
  }
}

export function sanitizeClientErrorMessage(message, fallback = 'Request failed') {
  const cleaned = sanitizeText(message || '').trim()
  if (!cleaned) return fallback
  return cleaned.slice(0, 200)
}
