import { verifyToken } from '../auth/jwt.js'

export function requireAuth(req, res, next) {
  // Prefer server-side session auth (httpOnly cookie managed by express-session).
  const sessionUser = req.session?.user
  if (sessionUser?.id && sessionUser?.email && sessionUser?.role) {
    req.user = {
      id: sessionUser.id,
      email: sessionUser.email,
      role: sessionUser.role,
      merchantName: sessionUser.merchantName ?? null,
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
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      role: decoded.role,
      merchantName: decoded.merchantName ?? null,
    }
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}
