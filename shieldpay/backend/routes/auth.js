import { Router } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { getDb } from '../db.js'
import { signToken } from '../auth/jwt.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const authRouter = Router()
const PASSWORD_RESET_TTL_MINUTES = 15
const MIN_PASSWORD_LEN = 12
const IMPERSONATE_WINDOW_MS = 10 * 60 * 1000
const IMPERSONATE_MAX_ATTEMPTS = 5
const MFA_TIME_STEP_SECONDS = 30
const impersonateBuckets = new Map()

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

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim()
  }
  return req.socket?.remoteAddress || ''
}

function nowStep() {
  return Math.floor(Date.now() / 1000 / MFA_TIME_STEP_SECONDS)
}

function otpForStep(secret, step) {
  const digest = crypto
    .createHmac('sha256', secret)
    .update(String(step), 'utf8')
    .digest('hex')
  const tail = digest.slice(-8)
  const num = Number.parseInt(tail, 16) % 1000000
  return String(num).padStart(6, '0')
}

function isValidMfaCode(secret, providedCode) {
  const code = String(providedCode || '').trim()
  if (!/^\d{6}$/.test(code)) return false
  const step = nowStep()
  return (
    otpForStep(secret, step) === code ||
    otpForStep(secret, step - 1) === code ||
    otpForStep(secret, step + 1) === code
  )
}

function consumeImpersonationQuota(adminId, ip) {
  const key = `${adminId}:${ip}`
  const now = Date.now()
  const bucket = impersonateBuckets.get(key)
  if (!bucket || now - bucket.windowStart > IMPERSONATE_WINDOW_MS) {
    impersonateBuckets.set(key, { windowStart: now, attempts: 1 })
    return true
  }
  if (bucket.attempts >= IMPERSONATE_MAX_ATTEMPTS) {
    return false
  }
  bucket.attempts += 1
  return true
}

function logImpersonationEvent({ adminUserId, adminEmail, targetUserId, targetEmail, success, reason, ip, userAgent }) {
  try {
    getDb()
      .prepare(
        `INSERT INTO impersonation_audit_logs
         (admin_user_id, admin_email, target_user_id, target_email, success, reason, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        adminUserId ?? null,
        adminEmail ?? null,
        targetUserId ?? null,
        targetEmail ?? null,
        success ? 1 : 0,
        reason ?? null,
        ip ?? null,
        userAgent ?? null,
      )
  } catch {
    // Do not block request path if audit insert fails.
  }
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

authRouter.post('/impersonate', requireAuth, (req, res, next) => {
  try {
    const { targetEmail, adminPassword, mfaCode, adminEmail } = req.body
    const targetEmailNorm = normalizeEmail(targetEmail)
    const adminEmailNorm = normalizeEmail(adminEmail)
    const ip = getClientIp(req)
    const userAgent = String(req.headers['user-agent'] || '')

    if (!targetEmailNorm || !adminPassword || !mfaCode || !adminEmailNorm) {
      return res
        .status(400)
        .json({ error: 'targetEmail, adminEmail, adminPassword, and mfaCode are required' })
    }
    if (!isValidEmail(targetEmailNorm) || !isValidEmail(adminEmailNorm)) {
      return res.status(400).json({ error: 'Invalid email format' })
    }
    if (!consumeImpersonationQuota(req.user.id, ip)) {
      logImpersonationEvent({
        adminUserId: req.user.id,
        adminEmail: req.user.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'rate_limited',
        ip,
        userAgent,
      })
      return res.status(429).json({ error: 'Too many impersonation attempts. Try again later.' })
    }

    const adminRow = getDb()
      .prepare('SELECT id, email, password_hash, role FROM users WHERE id = ?')
      .get(req.user.id)
    if (!adminRow || adminRow.role !== 'admin') {
      logImpersonationEvent({
        adminUserId: req.user.id,
        adminEmail: req.user.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'not_admin',
        ip,
        userAgent,
      })
      return res.status(403).json({ error: 'Admin only' })
    }
    if (adminEmailNorm !== normalizeEmail(adminRow.email)) {
      logImpersonationEvent({
        adminUserId: adminRow.id,
        adminEmail: adminRow.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'admin_email_mismatch',
        ip,
        userAgent,
      })
      return res.status(403).json({ error: 'Admin email verification failed' })
    }
    if (!bcrypt.compareSync(adminPassword, adminRow.password_hash)) {
      logImpersonationEvent({
        adminUserId: adminRow.id,
        adminEmail: adminRow.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'invalid_admin_password',
        ip,
        userAgent,
      })
      return res.status(401).json({ error: 'Invalid admin password' })
    }
    const mfaSecret = (process.env.ADMIN_MFA_SECRET || '').trim()
    if (!mfaSecret) {
      logImpersonationEvent({
        adminUserId: adminRow.id,
        adminEmail: adminRow.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'mfa_not_configured',
        ip,
        userAgent,
      })
      return res.status(503).json({ error: 'Admin MFA is not configured' })
    }
    if (!isValidMfaCode(mfaSecret, mfaCode)) {
      logImpersonationEvent({
        adminUserId: adminRow.id,
        adminEmail: adminRow.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'invalid_mfa_code',
        ip,
        userAgent,
      })
      return res.status(401).json({ error: 'Invalid MFA code' })
    }

    const target = getDb()
      .prepare('SELECT id, email, role, merchant_name FROM users WHERE email = ?')
      .get(targetEmailNorm)
    if (!target) {
      logImpersonationEvent({
        adminUserId: adminRow.id,
        adminEmail: adminRow.email,
        targetEmail: targetEmailNorm,
        success: false,
        reason: 'target_not_found',
        ip,
        userAgent,
      })
      return res.status(404).json({ error: 'Target user not found' })
    }
    const token = signToken({
      sub: target.id,
      email: target.email,
      role: target.role,
      merchantName: target.merchant_name,
    })
    logImpersonationEvent({
      adminUserId: adminRow.id,
      adminEmail: adminRow.email,
      targetUserId: target.id,
      targetEmail: target.email,
      success: true,
      reason: 'success',
      ip,
      userAgent,
    })
    res.json({
      impersonatedUser: { id: target.id, email: target.email, role: target.role },
      token,
    })
  } catch (e) {
    next(e)
  }
})
