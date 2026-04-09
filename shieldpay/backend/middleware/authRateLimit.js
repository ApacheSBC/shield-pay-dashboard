import { rateLimit } from 'express-rate-limit'
import slowDown from 'express-slow-down'
import { RedisStore } from 'rate-limit-redis'
import { createClient } from 'redis'
import { sanitizeErrorForLog } from '../utils/logSanitizer.js'

const AUTH_WINDOW_MS = 10 * 60 * 1000
const AUTH_LIMIT_DEFAULT = 20
const AUTH_LIMIT_LOGIN = 8
const AUTH_LIMIT_IMPERSONATE = 5

let sharedStore
let redisInitAttempted = false

async function initRedisStore() {
  if (redisInitAttempted) return sharedStore
  redisInitAttempted = true
  const redisUrl = String(process.env.RATE_LIMIT_REDIS_URL || '').trim()
  if (!redisUrl) return undefined

  try {
    const client = createClient({ url: redisUrl })
    client.on('error', (err) => {
      console.error('[ShieldPay] Redis client error for rate limit store:', sanitizeErrorForLog(err))
    })
    await client.connect()
    sharedStore = new RedisStore({
      sendCommand: (...args) => client.sendCommand(args),
      prefix: 'shieldpay:rl:',
    })
    console.log('[ShieldPay] Auth rate limiter using Redis store')
  } catch (err) {
    console.error('[ShieldPay] Redis unavailable for rate limit store, using in-memory fallback')
    console.error(sanitizeErrorForLog(err))
    sharedStore = undefined
  }
  return sharedStore
}

function authRateLimitKey(req) {
  const ip = String(req.ip || req.socket?.remoteAddress || '').trim().toLowerCase()
  const email = String(req.body?.email || req.body?.adminEmail || '').trim().toLowerCase()
  return email ? `${ip}:${email}` : ip
}

function createLimiter({ limit }) {
  return rateLimit({
    windowMs: AUTH_WINDOW_MS,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: authRateLimitKey,
    store: sharedStore,
    message: { error: 'Too many authentication attempts. Please try again later.' },
  })
}

function createSlowdown({ delayAfter }) {
  return slowDown({
    windowMs: AUTH_WINDOW_MS,
    delayAfter,
    delayMs: (used, req) => {
      const base = Math.max(used - delayAfter, 0)
      // Progressive delay to slow brute-force attempts without locking users out forever.
      return Math.min(base * 500, 8000)
    },
    keyGenerator: authRateLimitKey,
    store: sharedStore,
    validate: { delayMs: false },
  })
}

export async function buildAuthProtection() {
  await initRedisStore()
  return {
    login: [createSlowdown({ delayAfter: 3 }), createLimiter({ limit: AUTH_LIMIT_LOGIN })],
    register: [createSlowdown({ delayAfter: 5 }), createLimiter({ limit: AUTH_LIMIT_DEFAULT })],
    passwordResetRequest: [createSlowdown({ delayAfter: 4 }), createLimiter({ limit: AUTH_LIMIT_DEFAULT })],
    passwordResetConfirm: [createSlowdown({ delayAfter: 4 }), createLimiter({ limit: AUTH_LIMIT_DEFAULT })],
    impersonate: [createSlowdown({ delayAfter: 2 }), createLimiter({ limit: AUTH_LIMIT_IMPERSONATE })],
  }
}
