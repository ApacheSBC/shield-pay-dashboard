import jwt from 'jsonwebtoken'

const ACCESS_TOKEN_TTL = '15m'
const JWT_ISSUER = (process.env.JWT_ISSUER || 'shieldpay-api').trim()
const JWT_AUDIENCE = (process.env.JWT_AUDIENCE || 'shieldpay-client').trim()

function normalizePem(value) {
  return String(value || '')
    .trim()
    .replace(/\\n/g, '\n')
}

const privateKeyPem = normalizePem(process.env.JWT_PRIVATE_KEY)
const publicKeyPem = normalizePem(process.env.JWT_PUBLIC_KEY)

if (!privateKeyPem || !publicKeyPem) {
  throw new Error(
    'JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required (PEM format) for RS256 token signing/verification.',
  )
}
if (!JWT_ISSUER || !JWT_AUDIENCE) {
  throw new Error('JWT_ISSUER and JWT_AUDIENCE must be non-empty.')
}

export function signToken(payload, expiresIn = ACCESS_TOKEN_TTL) {
  return jwt.sign(payload, privateKeyPem, {
    algorithm: 'RS256',
    expiresIn,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  })
}

export function verifyToken(token) {
  return jwt.verify(token, publicKeyPem, {
    algorithms: ['RS256'],
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  })
}
