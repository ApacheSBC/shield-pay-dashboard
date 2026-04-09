const MAX_DISPLAY_LEN = 300

export function safeDisplayText(input, fallback = '') {
  if (input == null) return fallback
  const normalized = String(input)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  if (!normalized) return fallback
  if (normalized.length > MAX_DISPLAY_LEN) {
    return `${normalized.slice(0, MAX_DISPLAY_LEN)}…`
  }
  return normalized
}
