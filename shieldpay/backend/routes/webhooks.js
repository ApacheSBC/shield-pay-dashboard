import { Router } from 'express'
import { verifyInboundWebhookSignature } from '../utils/webhookSignature.js'

export const webhooksRouter = Router()

webhooksRouter.post('/incoming', (req, res) => {
  const rawBody = Buffer.isBuffer(req.body) ? req.body : null
  if (!rawBody) {
    return res.status(400).json({ error: 'Raw JSON body required' })
  }

  const verified = verifyInboundWebhookSignature({
    rawBody,
    timestampHeader: req.headers['x-webhook-timestamp'],
    signatureHeader: req.headers['x-webhook-signature'],
  })
  if (!verified.ok) {
    return res.status(401).json({ error: 'Invalid webhook signature' })
  }

  let event
  try {
    event = JSON.parse(rawBody.toString('utf8'))
  } catch {
    return res.status(400).json({ error: 'Invalid JSON payload' })
  }

  // Stub handler for demo app; persist/process events here for production.
  res.status(200).json({ received: true, eventType: event?.type ?? null })
})
