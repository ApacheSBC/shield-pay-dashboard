import 'dotenv/config'
import http from 'http'
import express from 'express'
import session from 'express-session'
import { RedisStore } from 'connect-redis'
import { createClient } from 'redis'
import helmet from 'helmet'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { initDb } from './backend/db.js'
import { apiRouter } from './backend/routes/index.js'
import { requestBodyLogger } from './backend/middleware/requestLogger.js'
import { sanitizeErrorForLog } from './backend/utils/logSanitizer.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = Number(process.env.PORT) || 8788
const isProd = process.env.NODE_ENV === 'production'
const MIN_SESSION_SECRET_LEN = 24
const sessionSecret = (process.env.SESSION_SECRET || '').trim()
const redisSessionUrl = String(process.env.REDIS_SESSION_URL || '').trim()
const DEFAULT_ALLOWED_ORIGINS = [`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`]
const corsAllowedOrigins = new Set(
  String(process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean),
)
if (corsAllowedOrigins.size === 0) {
  for (const origin of DEFAULT_ALLOWED_ORIGINS) corsAllowedOrigins.add(origin)
}

if (!sessionSecret) {
  console.error(
    'SESSION_SECRET is required. Set a strong random value in .env before starting the server.',
  )
  process.exit(1)
}
if (sessionSecret.length < MIN_SESSION_SECRET_LEN) {
  console.error(`SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LEN} characters long.`)
  process.exit(1)
}

try {
  await initDb()
} catch (err) {
  console.error('[ShieldPay] Database init failed (is better-sqlite3 built for your Node version?)')
  console.error(sanitizeErrorForLog(err))
  process.exit(1)
}

const app = express()
const connectSrc = new Set(["'self'"])
if (!isProd) {
  connectSrc.add('ws:')
  connectSrc.add('wss:')
  for (const origin of corsAllowedOrigins) connectSrc.add(origin)
}
if (isProd) {
  app.set('trust proxy', 1)
}

let sessionStore
if (redisSessionUrl) {
  try {
    const redisClient = createClient({ url: redisSessionUrl })
    redisClient.on('error', (err) => {
      console.error('[ShieldPay] Redis session-store client error:', sanitizeErrorForLog(err))
    })
    await redisClient.connect()
    sessionStore = new RedisStore({
      client: redisClient,
      prefix: 'shieldpay:sess:',
    })
    console.log('[ShieldPay] Using Redis session store')
  } catch (err) {
    console.error('[ShieldPay] Failed to initialize Redis session store')
    console.error(sanitizeErrorForLog(err))
    process.exit(1)
  }
} else if (isProd) {
  console.error('REDIS_SESSION_URL is required in production for secure session storage.')
  process.exit(1)
}

function normalizeOrigin(input) {
  try {
    const parsed = new URL(String(input))
    return parsed.origin
  } catch {
    return null
  }
}

function isOriginAllowed(originHeader) {
  const normalized = normalizeOrigin(originHeader)
  return Boolean(normalized && corsAllowedOrigins.has(normalized))
}

app.use((req, res, next) => {
  const origin = req.headers.origin
  if (!origin) return next()

  res.setHeader('Vary', 'Origin')

  if (!isOriginAllowed(origin)) {
    if (req.method === 'OPTIONS') {
      return res.status(403).end()
    }
    return res.status(403).json({ error: 'Origin not allowed' })
  }

  res.setHeader('Access-Control-Allow-Origin', normalizeOrigin(origin))
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
  res.setHeader('Access-Control-Max-Age', '600')

  if (req.method === 'OPTIONS') {
    return res.status(204).end()
  }
  next()
})

app.use(
  helmet({
    frameguard: { action: 'deny' }, // X-Frame-Options: DENY
    noSniff: true, // X-Content-Type-Options: nosniff
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        scriptSrc: isProd ? ["'self'"] : ["'self'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: Array.from(connectSrc),
      },
    },
    permissionsPolicy: {
      features: {
        camera: [],
        microphone: [],
        geolocation: [],
        payment: [],
      },
    },
  }),
)

app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: isProd ? 'strict' : 'lax',
      secure: isProd,
      maxAge: 86400000,
    },
  }),
)

// Inbound webhooks require raw body for HMAC signature verification.
app.use('/api/webhooks/incoming', express.raw({ type: 'application/json', limit: '256kb' }))
app.use(express.json())

// ARKO-LAB-05: log full request bodies (passwords, card fields) in development — unsafe pattern.
if (!isProd) {
  app.use(requestBodyLogger)
}

app.use('/api', apiRouter)

const server = http.createServer(app)

if (isProd) {
  const dist = path.join(__dirname, 'frontend', 'dist')
  if (!fs.existsSync(dist)) {
    console.error(
      '[ShieldPay] Production build missing. Run `npm run build` to create frontend/dist, then `npm start`.',
    )
    process.exit(1)
  }
  app.use(express.static(dist))
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next()
    res.sendFile(path.join(dist, 'index.html'))
  })
} else {
  const { createServer: createViteServer } = await import('vite')
  const vite = await createViteServer({
    root: path.join(__dirname, 'frontend'),
    server: {
      middlewareMode: true,
      hmr: { server },
    },
    appType: 'spa',
  })
  app.use(vite.middlewares)
}

app.use((err, req, res, next) => {
  console.error('[ShieldPay API error]', sanitizeErrorForLog(err))
  const status = Number.isInteger(err?.status) ? err.status : 500
  const messageByStatus = {
    400: 'Bad request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not found',
    409: 'Conflict',
    422: 'Unprocessable request',
    429: 'Too many requests',
  }
  const message = status >= 500 ? 'Internal server error' : messageByStatus[status] || 'Request failed'
  res.status(status).json({ error: message })
})

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(
      `[ShieldPay] Port ${PORT} is already in use. Set a free port in .env, e.g. PORT=8792, then run again.`,
    )
  } else {
    console.error(sanitizeErrorForLog(err))
  }
  process.exit(1)
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`ShieldPay listening at http://127.0.0.1:${PORT}`)
})
