import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeAndValidateWebhookUrl } from '../../backend/utils/webhookDestinationSafety.js'

const ORIGINAL_ALLOWED = process.env.WEBHOOK_ALLOWED_HOSTS

function restoreEnv() {
  if (ORIGINAL_ALLOWED == null) {
    delete process.env.WEBHOOK_ALLOWED_HOSTS
  } else {
    process.env.WEBHOOK_ALLOWED_HOSTS = ORIGINAL_ALLOWED
  }
}

test('rejects localhost and private address webhook targets', async (t) => {
  t.after(restoreEnv)
  delete process.env.WEBHOOK_ALLOWED_HOSTS

  const local = await normalizeAndValidateWebhookUrl('http://localhost:8788/hook')
  const privateV4 = await normalizeAndValidateWebhookUrl('https://192.168.1.10/hook')
  const privateExotic = await normalizeAndValidateWebhookUrl('https://0177.0.0.1/hook')

  assert.equal(local, null)
  assert.equal(privateV4, null)
  assert.equal(privateExotic, null)
})

test('normalizes valid direct public-ip webhook URL and strips fragments', async (t) => {
  t.after(restoreEnv)
  delete process.env.WEBHOOK_ALLOWED_HOSTS

  const safeUrl = await normalizeAndValidateWebhookUrl('https://1.1.1.1/webhook#ignore-me')
  assert.equal(safeUrl, 'https://1.1.1.1/webhook')
})

test('enforces hostname allowlist when configured', async (t) => {
  t.after(restoreEnv)
  process.env.WEBHOOK_ALLOWED_HOSTS = 'hooks.example.com'

  const blocked = await normalizeAndValidateWebhookUrl('https://api.other.com/hook')
  assert.equal(blocked, null)
})
