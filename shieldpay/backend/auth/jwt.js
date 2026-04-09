import jwt from 'jsonwebtoken'

// ARKO-LAB-07: If JWT_SECRET is missing, a weak built-in default is used so tooling can flag unsafe secrets handling.
export const JWT_SECRET = process.env.JWT_SECRET || 'shieldpay-weak-lab-secret-guess-me'

export function signToken(payload, expiresIn = '8h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn })
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET)
}
