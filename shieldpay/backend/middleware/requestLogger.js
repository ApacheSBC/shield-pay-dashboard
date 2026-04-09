const SENSITIVE_KEY_RE =
  /(password|newPassword|adminPassword|token|authorization|jwt|secret|api[_-]?key|cvv|pan|card(number)?)/i

function redactValue(value) {
  if (value == null) return value
  if (Array.isArray(value)) return value.map((v) => redactValue(v))
  if (typeof value === 'object') return redactObject(value)
  if (typeof value === 'string') return '[REDACTED]'
  return '[REDACTED]'
}

function redactObject(input) {
  const out = {}
  for (const [key, value] of Object.entries(input)) {
    if (SENSITIVE_KEY_RE.test(key)) {
      out[key] = '[REDACTED]'
    } else if (value && typeof value === 'object') {
      out[key] = redactValue(value)
    } else {
      out[key] = value
    }
  }
  return out
}

export function requestBodyLogger(req, res, next) {
  if (req.path.startsWith('/api') && req.method !== 'GET' && req.body && Object.keys(req.body).length) {
    const redacted = redactObject(req.body)
    console.log('[ShieldPay dev log]', req.method, req.path, JSON.stringify(redacted))
  }
  next()
}
