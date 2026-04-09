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
