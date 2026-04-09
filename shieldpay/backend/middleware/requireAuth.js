import { verifyToken } from '../auth/jwt.js'
import { getDb } from '../db.js'

function loadUserAuthState(userId) {
  return getDb()
    .prepare('SELECT id, email, role, merchant_name, session_version FROM users WHERE id = ?')
    .get(userId)
}

export function requireAuth(req, res, next) {
  // Prefer server-side session auth (httpOnly cookie managed by express-session).
  const sessionUser = req.session?.user
  if (sessionUser?.id && sessionUser?.email && sessionUser?.role) {
    const row = loadUserAuthState(sessionUser.id)
    const sessionVersion = Number(sessionUser.sessionVersion ?? -1)
    if (!row || sessionVersion !== Number(row.session_version ?? 0)) {
      if (req.session) req.session.user = null
      return res.status(401).json({ error: 'Session expired. Please log in again.' })
    }
    req.user = {
      id: row.id,
      email: row.email,
      role: row.role,
      merchantName: row.merchant_name ?? null,
    }
    return next()
  }

  // Backward-compatible Bearer JWT path.
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) {
    return res.status(401).json({ error: 'Missing token' })
  }
  try {
    const decoded = verifyToken(token)
    const row = loadUserAuthState(decoded.sub)
    const tokenVersion = Number(decoded.sv ?? -1)
    if (!row || tokenVersion !== Number(row.session_version ?? 0)) {
      return res.status(401).json({ error: 'Session expired. Please log in again.' })
    }
    req.user = {
      id: row.id,
      email: row.email,
      role: row.role,
      merchantName: row.merchant_name ?? null,
    }
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}
