import jwt from 'jsonwebtoken'

const MIN_JWT_SECRET_LEN = 32
const rawJwtSecret = (process.env.JWT_SECRET || '').trim()

if (!rawJwtSecret) {
  throw new Error(
    'JWT_SECRET is required. Set a strong random value in .env (example: openssl rand -base64 48).',
  )
}
if (rawJwtSecret.length < MIN_JWT_SECRET_LEN) {
  throw new Error(`JWT_SECRET must be at least ${MIN_JWT_SECRET_LEN} characters long.`)
}

export const JWT_SECRET = rawJwtSecret

export function signToken(payload, expiresIn = '8h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn })
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET)
}
