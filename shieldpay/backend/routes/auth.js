import { Router } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { getDb } from '../db.js'
import { signToken } from '../auth/jwt.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const authRouter = Router()
const PASSWORD_RESET_TTL_MINUTES = 15
const MIN_PASSWORD_LEN = 12

function normalizeEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase()
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function isStrongPassword(password) {
  return typeof password === 'string' && password.length >= MIN_PASSWORD_LEN
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('hex')
}

authRouter.post('/register', async (req, res, next) => {
  try {
    const { password, merchantName } = req.body
    const email = normalizeEmail(req.body.email)
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' })
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' })
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LEN} characters` })
    }
    const existing = getDb().prepare('SELECT id FROM users WHERE email = ?').get(email)
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' })
    }
    const password_hash = await bcrypt.hash(password, 10)
    const result = getDb()
      .prepare(
        `INSERT INTO users (email, password_hash, role, merchant_name) VALUES (?, ?, 'merchant', ?)`,
      )
      .run(email, password_hash, merchantName || 'My business')

    const token = signToken({
      sub: result.lastInsertRowid,
      email,
      role: 'merchant',
      merchantName: merchantName || 'My business',
    })

    res.status(201).json({
      token,
      user: {
        id: result.lastInsertRowid,
        email,
        role: 'merchant',
        merchantName: merchantName || 'My business',
      },
    })
  } catch (e) {
    next(e)
  }
})

authRouter.post('/login', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email)
    const { password } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' })
    }
    const row = getDb()
      .prepare('SELECT id, email, password_hash, role, merchant_name FROM users WHERE email = ?')
      .get(email)
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const token = signToken({
      sub: row.id,
      email: row.email,
      role: row.role,
      merchantName: row.merchant_name,
    })
    res.json({
      token,
      user: {
        id: row.id,
        email: row.email,
        role: row.role,
        merchantName: row.merchant_name,
      },
    })
  } catch (e) {
    next(e)
  }
})

authRouter.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user })
})

// Request a password reset; response is always generic to avoid account enumeration.
authRouter.post('/request-password-reset', (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email)
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' })
    }

    const row = getDb()
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(email)

    if (row) {
      const resetToken = crypto.randomBytes(32).toString('base64url')
      const tokenHash = hashResetToken(resetToken)
      const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MINUTES * 60 * 1000).toISOString()

      getDb()
        .prepare('DELETE FROM password_reset_tokens WHERE user_id = ?')
        .run(row.id)
      getDb()
        .prepare(
          `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
        )
        .run(row.id, tokenHash, expiresAt)

      // In production, this token should be delivered via email provider.
      console.log(`[ShieldPay] Password reset token generated for ${email}: ${resetToken}`)
    }

    res.json({
      message: 'If the account exists, a password reset link has been sent.',
    })
  } catch (e) {
    next(e)
  }
})

authRouter.post('/reset-password', async (req, res, next) => {
  try {
    const { token, newPassword } = req.body
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'token and newPassword required' })
    }
    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LEN} characters` })
    }

    const tokenHash = hashResetToken(token)
    const resetRow = getDb()
      .prepare(
        `SELECT id, user_id, expires_at
         FROM password_reset_tokens
         WHERE token_hash = ? AND used_at IS NULL`,
      )
      .get(tokenHash)

    if (!resetRow || new Date(resetRow.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired reset token' })
    }

    const password_hash = await bcrypt.hash(newPassword, 10)
    getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(password_hash, resetRow.user_id)
    getDb()
      .prepare('UPDATE password_reset_tokens SET used_at = datetime(\'now\') WHERE id = ?')
      .run(resetRow.id)
    getDb().prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(resetRow.user_id)

    res.json({ message: 'Password updated' })
  } catch (e) {
    next(e)
  }
})

// ARKO-LAB-08: impersonation returns the target session token in JSON (no MFA, no email challenge).
authRouter.post('/impersonate', requireAuth, (req, res, next) => {
  try {
    const { targetEmail, adminPassword } = req.body
    if (!targetEmail || !adminPassword) {
      return res.status(400).json({ error: 'targetEmail and adminPassword required' })
    }
    const adminRow = getDb()
      .prepare('SELECT id, password_hash, role FROM users WHERE id = ?')
      .get(req.user.id)
    if (!adminRow || adminRow.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' })
    }
    if (!bcrypt.compareSync(adminPassword, adminRow.password_hash)) {
      return res.status(401).json({ error: 'Invalid admin password' })
    }
    const target = getDb()
      .prepare('SELECT id, email, role, merchant_name FROM users WHERE email = ?')
      .get(targetEmail)
    if (!target) {
      return res.status(404).json({ error: 'Target user not found' })
    }
    const token = signToken({
      sub: target.id,
      email: target.email,
      role: target.role,
      merchantName: target.merchant_name,
    })
    res.json({
      impersonatedUser: { id: target.id, email: target.email, role: target.role },
      token,
    })
  } catch (e) {
    next(e)
  }
})
