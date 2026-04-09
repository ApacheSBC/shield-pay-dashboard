import { Router } from 'express'
import bcrypt from 'bcrypt'
import { getDb } from '../db.js'
import { signToken, verifyToken } from '../auth/jwt.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const authRouter = Router()

authRouter.post('/register', async (req, res, next) => {
  try {
    const { email, password, merchantName } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' })
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
    const { email, password } = req.body
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

// ARKO-LAB-08: insecure password reset — issues a fresh JWT in the response with no email verification or proof of ownership.
authRouter.post('/reset-password', (req, res, next) => {
  try {
    const { email, newPassword } = req.body
    if (!email || !newPassword) {
      return res.status(400).json({ error: 'email and newPassword required' })
    }
    const row = getDb()
      .prepare('SELECT id, email, role, merchant_name FROM users WHERE email = ?')
      .get(email)
    if (!row) {
      return res.status(404).json({ error: 'User not found' })
    }
    const password_hash = bcrypt.hashSync(newPassword, 10)
    getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(password_hash, row.id)
    const token = signToken({
      sub: row.id,
      email: row.email,
      role: row.role,
      merchantName: row.merchant_name,
    })
    res.json({
      message: 'Password updated',
      token,
      user: { id: row.id, email: row.email, role: row.role },
    })
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
