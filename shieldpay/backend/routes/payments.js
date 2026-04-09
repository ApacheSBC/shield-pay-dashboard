import { Router } from 'express'
import crypto from 'crypto'
import { z } from 'zod'
import { getDb } from '../db.js'
import { requireAuth } from '../middleware/requireAuth.js'
import { cardRowToApi, encryptField, transactionRowToApiMasked } from '../crypto/cardFieldCrypto.js'
import { validateRequest } from '../middleware/validateRequest.js'
import { sanitizeErrorForLog } from '../utils/logSanitizer.js'
import { normalizeAndValidateWebhookUrl, parseWebhookAllowedHosts } from '../utils/webhookDestinationSafety.js'

export const paymentsRouter = Router()
paymentsRouter.use(requireAuth)
const paymentProcessBodySchema = z.object({
  cardId: z.coerce.number().int().positive(),
  customerId: z.coerce.number().int().positive().optional(),
  amountDollars: z.coerce.number().positive(),
  description: z.string().trim().max(200).optional(),
})

const webhookAllowedHosts = parseWebhookAllowedHosts()

async function dispatchMerchantWebhooks(merchantId, eventPayload) {
  const hooks = getDb().prepare('SELECT url, secret FROM webhooks WHERE merchant_id = ? AND active = 1').all(merchantId)
  if (!hooks.length) return
  const body = JSON.stringify(eventPayload)
  const timestamp = String(Math.floor(Date.now() / 1000))

  await Promise.all(
    hooks.map(async (hook) => {
      const safeUrl = await normalizeAndValidateWebhookUrl(hook.url, webhookAllowedHosts)
      if (!safeUrl) return

      const headers = {
        'content-type': 'application/json',
        'x-webhook-timestamp': timestamp,
      }
      if (hook.secret) {
        const sig = crypto.createHmac('sha256', String(hook.secret)).update(`${timestamp}.${body}`, 'utf8').digest('hex')
        headers['x-webhook-signature'] = `sha256=${sig}`
      }

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 5000)
      try {
        await fetch(safeUrl, {
          method: 'POST',
          headers,
          body,
          signal: controller.signal,
        })
      } catch (err) {
        console.warn('[ShieldPay webhook delivery]', sanitizeErrorForLog(err))
      } finally {
        clearTimeout(timeout)
      }
    }),
  )
}

paymentsRouter.post('/process', validateRequest({ body: paymentProcessBodySchema }), (req, res, next) => {
  try {
    if (req.user.role !== 'merchant') {
      return res.status(403).json({ error: 'Merchants only' })
    }
    const { cardId, customerId, amountDollars, description } = req.body
    if (!cardId || amountDollars == null) {
      return res.status(400).json({ error: 'cardId and amountDollars required' })
    }
    const cardRow = getDb()
      .prepare('SELECT * FROM cards WHERE id = ? AND merchant_id = ?')
      .get(cardId, req.user.id)
    if (!cardRow) return res.status(400).json({ error: 'Invalid card' })
    const card = cardRowToApi(cardRow)
    const amount_cents = Math.round(Number(amountDollars) * 100)
    if (!Number.isFinite(amount_cents) || amount_cents <= 0) {
      return res.status(400).json({ error: 'Invalid amount' })
    }
    let custId = card.customer_id
    if (customerId != null && customerId !== '') {
      const customerRow = getDb()
        .prepare('SELECT id FROM customers WHERE id = ? AND merchant_id = ?')
        .get(customerId, req.user.id)
      if (!customerRow) {
        return res.status(400).json({ error: 'Invalid customer' })
      }
      custId = customerRow.id
    }
    const panSnap = encryptField(card.pan_plain)
    const r = getDb()
      .prepare(
        `INSERT INTO transactions (merchant_id, customer_id, card_id, amount_cents, currency, status, description, pan_snapshot_encrypted)
         VALUES (?, ?, ?, ?, 'USD', 'captured', ?, ?)`,
      )
      .run(req.user.id, custId, cardId, amount_cents, description || 'Payment', panSnap)
    const txRow = getDb().prepare('SELECT * FROM transactions WHERE id = ?').get(r.lastInsertRowid)
    const tx = transactionRowToApiMasked(txRow)
    const webhookEvent = {
      type: 'payment.captured',
      merchantId: req.user.id,
      transaction: tx,
    }
    void dispatchMerchantWebhooks(req.user.id, webhookEvent)
    res.status(201).json({
      transaction: tx,
    })
  } catch (e) {
    next(e)
  }
})
