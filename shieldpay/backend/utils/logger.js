import { sanitizeErrorForLog, sanitizeText } from './logSanitizer.js'

function sanitizeMeta(meta) {
  if (meta == null) return undefined
  if (Array.isArray(meta)) return meta.map((v) => sanitizeMeta(v))
  if (meta instanceof Error) return sanitizeErrorForLog(meta)
  if (typeof meta === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(meta)) out[k] = sanitizeMeta(v)
    return out
  }
  if (typeof meta === 'string') return sanitizeText(meta)
  return meta
}

function emit(level, message, meta) {
  const payload = {
    ts: new Date().toISOString(),
    level,
    msg: sanitizeText(String(message || '')),
  }
  const safeMeta = sanitizeMeta(meta)
  if (safeMeta !== undefined) payload.meta = safeMeta
  const line = JSON.stringify(payload)
  if (level === 'error') {
    console.error(line)
  } else if (level === 'warn') {
    console.warn(line)
  } else {
    console.log(line)
  }
}

export function logInfo(message, meta) {
  emit('info', message, meta)
}

export function logWarn(message, meta) {
  emit('warn', message, meta)
}

export function logError(message, meta) {
  emit('error', message, meta)
}
