import { verifyToken } from '../auth/jwt.js'

export function requireAuth(req, res, next) {
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
