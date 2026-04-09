const MAX_ERROR_LEN = 160

/**
 * Convert untrusted API error payloads to safe, short plain text for UI display.
 */
export function safeErrorMessage(input, fallback = 'Request failed') {
  if (typeof input !== 'string') return fallback
  const normalized = input
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  if (!normalized) return fallback
  if (normalized.length > MAX_ERROR_LEN) {
    return `${normalized.slice(0, MAX_ERROR_LEN)}…`
  }
  return normalized
}
