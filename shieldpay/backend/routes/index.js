import { Router } from 'express'
import { healthRouter } from './health.js'
import { authRouter } from './auth.js'
import { customersRouter } from './customers.js'
import { cardsRouter } from './cards.js'
import { transactionsRouter } from './transactions.js'
import { paymentsRouter } from './payments.js'
import { adminRouter } from './admin.js'
import { settingsRouter } from './settings.js'
import { statsRouter } from './stats.js'

export const apiRouter = Router()

apiRouter.use(healthRouter)
apiRouter.use('/auth', authRouter)
apiRouter.use('/customers', customersRouter)
apiRouter.use('/cards', cardsRouter)
apiRouter.use('/transactions', transactionsRouter)
apiRouter.use('/payments', paymentsRouter)
apiRouter.use('/admin', adminRouter)
apiRouter.use('/settings', settingsRouter)
apiRouter.use('/stats', statsRouter)

apiRouter.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})
