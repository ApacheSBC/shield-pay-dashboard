import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

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

test('frontend auth avoids localStorage token persistence and uses cookies', () => {
  const authContextFile = read('frontend/src/context/AuthContext.jsx')
  const apiClientFile = read('frontend/src/api/client.js')

  // Auth context should not persist JWT/user data in browser storage.
  assert.doesNotMatch(authContextFile, /localStorage|sessionStorage|getItem\(|setItem\(|removeItem\(/)

  // API client should rely on cookie-based auth for session/JWT transport.
  assert.match(apiClientFile, /withCredentials:\s*true/)
  assert.doesNotMatch(apiClientFile, /Authorization/)
})

test('global API error handler returns generic messages only', () => {
  const serverFile = read('server.js')

  // Server logs sanitized details internally.
  assert.match(serverFile, /console\.error\('\[ShieldPay API error\]', sanitizeErrorForLog\(err\)\)/)

  // Response should use generic mapped messages and never expose stack/body.
  assert.match(serverFile, /const messageByStatus = \{/)
  assert.match(serverFile, /status >= 500 \? 'Internal server error' : messageByStatus\[status\] \|\| 'Request failed'/)
  assert.match(serverFile, /res\.status\(status\)\.json\(\{ error: message \}\)/)
  assert.doesNotMatch(serverFile, /res\.status\(status\)\.json\(\{[\s\S]*stack[\s\S]*\}\)/)
  assert.doesNotMatch(serverFile, /res\.status\(status\)\.json\(\{[\s\S]*req\.body[\s\S]*\}\)/)
  assert.doesNotMatch(serverFile, /res\.status\(status\)\.json\(\{[\s\S]*err\.message[\s\S]*\}\)/)
})

test('card and customer mutation routes enforce merchant ownership checks', () => {
  const cardsFile = read('backend/routes/cards.js')
  const customersFile = read('backend/routes/customers.js')

  // Cards: update/delete checks and mutations must include merchant_id scoping.
  assert.match(cardsFile, /SELECT \* FROM cards WHERE id = \? AND merchant_id = \?/)
  assert.match(cardsFile, /UPDATE cards[\s\S]*WHERE id = \? AND merchant_id = \?/)
  assert.match(cardsFile, /SELECT id FROM cards WHERE id = \? AND merchant_id = \?/)
  assert.match(cardsFile, /DELETE FROM cards WHERE id = \? AND merchant_id = \?/)

  // Customers: update/delete existence checks and mutations must include merchant_id scoping.
  assert.match(customersFile, /SELECT \* FROM customers WHERE id = \? AND merchant_id = \?/)
  assert.match(customersFile, /UPDATE customers[\s\S]*WHERE id = \? AND merchant_id = \?/)
  assert.match(customersFile, /SELECT id FROM customers WHERE id = \? AND merchant_id = \?/)
  assert.match(customersFile, /DELETE FROM customers WHERE id = \? AND merchant_id = \?/)
})

test('webhook registration validates URLs to mitigate SSRF', () => {
  const settingsFile = read('backend/routes/settings.js')
  const webhookSafetyFile = read('backend/utils/webhookDestinationSafety.js')

  // Endpoint must validate incoming URL and reject unsafe targets.
  assert.match(settingsFile, /settingsRouter\.post\('\/webhooks'/)
  assert.match(settingsFile, /const safeUrl = validateWebhookUrl\(url\)/)
  assert.match(settingsFile, /Invalid webhook URL\. Use public http\(s\) endpoint only\./)

  // Validation must block local/private targets across hostnames, IPv4, IPv6, and exotic IPv4 notation.
  assert.match(settingsFile, /normalizeAndValidateWebhookUrl/)
  assert.match(settingsFile, /parseWebhookAllowedHosts/)
  assert.match(webhookSafetyFile, /PRIVATE_HOST_RE/)
  assert.match(webhookSafetyFile, /parseIpv4AnyNotation/)
  assert.match(webhookSafetyFile, /await dnsLookup\(/)
  assert.match(webhookSafetyFile, /WEBHOOK_ALLOWED_HOSTS/)
})

test('database seed requires admin credentials from environment', () => {
  const dbFile = read('backend/db.js')

  // Seed must read admin credentials from env and fail closed if missing.
  assert.match(dbFile, /process\.env\.ADMIN_EMAIL/)
  assert.match(dbFile, /process\.env\.ADMIN_PASSWORD/)
  assert.match(dbFile, /Initial seed requires ADMIN_EMAIL and ADMIN_PASSWORD in environment/)

  // Prevent regressions to known weak fallback defaults (use split fragments to avoid signature false positives).
  const legacyAdminEmailPattern = new RegExp(['admin', '@', 'shieldpay', '\\.', 'lab'].join(''), 'i')
  const legacyAdminPasswordPattern = new RegExp(['Change', 'Me', 'Admin', '123!'].join(''), 'i')
  assert.doesNotMatch(dbFile, legacyAdminEmailPattern)
  assert.doesNotMatch(dbFile, legacyAdminPasswordPattern)
})

test('API key labels are sanitized in backend and safely rendered in frontend', () => {
  const settingsRouteFile = read('backend/routes/settings.js')
  const settingsPageFile = read('frontend/src/pages/Settings.jsx')

  // Backend sanitizes labels before persistence and response.
  assert.match(settingsRouteFile, /function sanitizeLabel\(/)
  assert.match(settingsRouteFile, /const labelSafe = sanitizeLabel\(label\)/)
  assert.match(settingsRouteFile, /label:\s*sanitizeLabel\(k\.label\)/)

  // Frontend renders labels via safe display helper.
  assert.match(settingsPageFile, /safeDisplayText\(k\.label\)/)
})

test('payment processing validates optional customer ownership for merchant', () => {
  const paymentsFile = read('backend/routes/payments.js')
  const webhookSafetyFile = read('backend/utils/webhookDestinationSafety.js')

  // Customer ownership check must exist when customerId is provided.
  assert.match(paymentsFile, /if \(customerId != null && customerId !== ''\)/)
  assert.match(paymentsFile, /SELECT id FROM customers WHERE id = \? AND merchant_id = \?/)
  assert.match(paymentsFile, /Invalid customer/)
  assert.match(paymentsFile, /normalizeAndValidateWebhookUrl/)
  assert.match(paymentsFile, /parseWebhookAllowedHosts/)
  assert.match(paymentsFile, /void dispatchMerchantWebhooks\(/)
  assert.match(webhookSafetyFile, /export async function normalizeAndValidateWebhookUrl/)
})

test('impersonation endpoint enforces step-up controls and audit logging', () => {
  const authFile = read('backend/routes/auth.js')

  // Endpoint must require auth and dedicated impersonation rate limiting.
  assert.match(authFile, /authRouter\.post\(\s*'\/impersonate'/)
  assert.match(authFile, /requireAuth/)
  assert.match(authFile, /\.\.\.authProtection\.impersonate/)
  assert.match(authFile, /consumeImpersonationQuota/)

  // Step-up verification: admin email verification + admin password + MFA code.
  assert.match(authFile, /adminEmail/)
  assert.match(authFile, /adminEmailNorm !== normalizeEmail\(adminRow\.email\)/)
  assert.match(authFile, /bcrypt\.compareSync\(adminPassword,\s*adminRow\.password_hash\)/)
  assert.match(authFile, /isValidMfaCode\(mfaSecret,\s*mfaCode\)/)

  // Comprehensive audit logging on impersonation flow.
  assert.match(authFile, /function logImpersonationEvent\(/)
  assert.match(authFile, /INSERT INTO impersonation_audit_logs/)
  assert.match(authFile, /reason:\s*'rate_limited'/)
  assert.match(authFile, /reason:\s*'success'/)
})

test('password reset flow requires reset token and avoids legacy unauthenticated email reset', () => {
  const authFile = read('backend/routes/auth.js')

  // Modern flow: request-reset endpoint plus token-based reset endpoint.
  assert.match(authFile, /authRouter\.post\(\s*'\/request-password-reset'/)
  assert.match(authFile, /authRouter\.post\(\s*'\/reset-password'/)
  assert.match(authFile, /token:\s*z\.string\(\)\.min\(1\)\.max\(512\)/)
  assert.match(authFile, /newPassword:\s*z\.string\(\)\.min\(MIN_PASSWORD_LEN\)/)
  assert.match(authFile, /hashResetToken\(token\)/)
  assert.match(authFile, /FROM password_reset_tokens/)
  assert.match(authFile, /Invalid or expired reset token/)

  // Guard against regression to insecure direct reset by email.
  const resetSection = authFile.match(/authRouter\.post\(\s*'\/reset-password'[\s\S]*?\n\)\n\nauthRouter\.post\(\s*'\/impersonate'/)
  assert.ok(resetSection, 'reset-password section should be present')
  const text = resetSection[0]
  assert.doesNotMatch(text, /email\s*[,}]/)
  assert.doesNotMatch(text, /signToken\(/)
})

test('webhook auth helper returns object contract consumed by callers', () => {
  const webhookSigFile = read('backend/utils/webhookSignature.js')
  const webhookRouteFile = read('backend/routes/webhooks.js')

  // Helper returns object contract for success and mismatch cases.
  assert.match(webhookSigFile, /if \(!provided\) return \{ ok: false, reason: 'missing_auth_token' \}/)
  assert.match(webhookSigFile, /const isMatch = safeEqualString\(provided,\s*configured\)/)
  assert.match(webhookSigFile, /if \(!isMatch\) return \{ ok: false, reason: 'auth_token_mismatch' \}/)
  assert.match(webhookSigFile, /return \{ ok: true \}/)

  // Caller expects .ok contract and denies unauthorized requests.
  assert.match(webhookRouteFile, /const auth = verifyInboundWebhookAuthToken\(/)
  assert.match(webhookRouteFile, /if \(!auth\.ok\)/)
  assert.match(webhookRouteFile, /Unauthorized webhook request/)
})

test('log sanitizer masks sensitive values in log text', async () => {
  const mod = await import(pathToFileURL(path.join(projectRoot, 'backend/utils/logSanitizer.js')).href)
  const { sanitizeText } = mod

  const raw =
    'password=Secret123 bearer Bearer abcdefghijklmnopqrstuvwxyz123456 email john.doe@example.com ' +
    'card 4111111111111111 cvv=123 token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature'
  const out = sanitizeText(raw)

  assert.doesNotMatch(out, /Secret123/)
  assert.doesNotMatch(out, /john\.doe@example\.com/i)
  assert.doesNotMatch(out, /4111111111111111/)
  assert.doesNotMatch(out, /eyJhbGci/i)
  assert.match(out, /\[REDACTED\]|\*\*\*EMAIL\*\*\*|\*\*\*CARD\*\*\*|\*\*\*CVV\*\*\*/)
})
