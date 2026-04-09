import 'dotenv/config'
import http from 'http'
import express from 'express'
import session from 'express-session'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { initDb } from './backend/db.js'
import { apiRouter } from './backend/routes/index.js'
import { requestBodyLogger } from './backend/middleware/requestLogger.js'
import { sanitizeClientErrorMessage, sanitizeErrorForLog } from './backend/utils/logSanitizer.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = Number(process.env.PORT) || 8788
const isProd = process.env.NODE_ENV === 'production'
const MIN_SESSION_SECRET_LEN = 24
const sessionSecret = (process.env.SESSION_SECRET || '').trim()

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

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: 86400000,
    },
  }),
)

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
  const message =
    status >= 500 ? 'Internal server error' : sanitizeClientErrorMessage(err?.message, 'Request failed')
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
