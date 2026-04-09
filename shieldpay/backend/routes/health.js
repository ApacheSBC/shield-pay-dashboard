import { Router } from 'express'

export const healthRouter = Router()

healthRouter.get('/health', (req, res) => {
  res.json({ ok: true, service: 'shieldpay', time: new Date().toISOString() })
})
