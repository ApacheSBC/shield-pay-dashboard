import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '..', '..')

function read(relPath) {
  return fs.readFileSync(path.join(projectRoot, relPath), 'utf8')
}

test('JWT implementation uses RS256 with required claims checks', () => {
  const jwtFile = read('backend/auth/jwt.js')
  assert.match(jwtFile, /algorithm:\s*'RS256'/)
  assert.match(jwtFile, /issuer:\s*JWT_ISSUER/)
  assert.match(jwtFile, /audience:\s*JWT_AUDIENCE/)
  assert.match(jwtFile, /algorithms:\s*\['RS256'\]/)
})

test('auth routes expose refresh endpoint and rotate refresh tokens', () => {
  const authFile = read('backend/routes/auth.js')
  assert.match(authFile, /authRouter\.post\('\/refresh'/)
  assert.match(authFile, /revokeRefreshTokenByHash/)
  assert.match(authFile, /issueRefreshToken/)
})

test('server config enforces secure session store in production', () => {
  const serverFile = read('server.js')
  assert.match(serverFile, /REDIS_SESSION_URL is required in production/)
  assert.match(serverFile, /sameSite:\s*isProd \? 'strict' : 'lax'/)
})

test('admin routes enforce server-side RBAC for all /api/admin endpoints', () => {
  const indexFile = read('backend/routes/index.js')
  const adminFile = read('backend/routes/admin.js')

  // Ensure /api/admin is mounted through the dedicated admin router.
  assert.match(indexFile, /apiRouter\.use\('\/admin',\s*adminRouter\)/)

  // Ensure the admin router always requires authentication.
  assert.match(adminFile, /adminRouter\.use\(requireAuth\)/)

  // Ensure non-admin users are explicitly blocked server-side.
  assert.match(adminFile, /req\.user\?\.role\s*!==\s*'admin'/)
  assert.match(adminFile, /res\.status\(403\)\.json\(\{\s*error:\s*'Admin only'\s*\}\)/)
})

test('request logger redacts and sanitizes request bodies before logging', () => {
  const requestLoggerFile = read('backend/middleware/requestLogger.js')

  // Ensure a sensitive-field regex exists and includes core secrets.
  assert.match(requestLoggerFile, /SENSITIVE_KEY_RE/)
  assert.match(requestLoggerFile, /(password|token|authorization|cvv|pan|card)/i)

  // Ensure logs are based on a redacted object, not raw req.body.
  assert.match(requestLoggerFile, /const redacted = redactObject\(req\.body\)/)
  assert.doesNotMatch(requestLoggerFile, /console\.log\([^)]*req\.body[^)]*\)/)

  // Ensure output is passed through centralized sanitizer before console output.
  assert.match(requestLoggerFile, /sanitizeText\(JSON\.stringify\(redacted\)\)/)
})

test('settings page keeps API secret in ephemeral reveal flow, not message banner', () => {
  const settingsFile = read('frontend/src/pages/Settings.jsx')

  // Dedicated ephemeral secret state exists.
  assert.match(settingsFile, /const \[ephemeralSecret,\s*setEphemeralSecret\] = useState\(''\)/)
  assert.match(settingsFile, /setEphemeralSecret\(data\.secret\)/)

  // Secret reveal is auto-cleared and can be manually cleared.
  assert.match(settingsFile, /setTimeout\(\(\) => \{\s*setEphemeralSecret\(''\)/)
  assert.match(settingsFile, /onClick=\{\(\) => \{\s*setEphemeralSecret\(''\)/)

  // Prevent future regressions where secret is copied into general message UI state.
  assert.doesNotMatch(settingsFile, /setMsg\(\s*data\.secret\s*\)/)
})

test('password reset request endpoint stays enumeration-safe', () => {
  const authFile = read('backend/routes/auth.js')

  // Ensure reset-request flow exists with a generic success message.
  assert.match(authFile, /authRouter\.post\(\s*'\/request-password-reset'/)
  assert.match(authFile, /If the account exists, a password reset link has been sent\./)

  // Ensure non-existent users do not trigger explicit 404/not-found responses in this flow.
  const requestResetSection = authFile.match(
    /authRouter\.post\(\s*'\/request-password-reset'[\s\S]*?\n\)\n\nauthRouter\.post\(\s*'\/reset-password'/,
  )
  assert.ok(requestResetSection, 'request-password-reset section should be present')
  const sectionText = requestResetSection[0]
  assert.doesNotMatch(sectionText, /status\(404\)/)
  assert.doesNotMatch(sectionText, /not found/i)
})
