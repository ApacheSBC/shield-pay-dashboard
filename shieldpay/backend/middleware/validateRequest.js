import { z } from 'zod'

function firstIssueMessage(error) {
  const issue = error?.issues?.[0]
  if (!issue) return 'Invalid request input'
  const path = issue.path?.length ? issue.path.join('.') : 'request'
  return `${path}: ${issue.message}`
}

export function validateRequest({ body, params, query }) {
  return (req, res, next) => {
    try {
      if (body) req.body = body.parse(req.body ?? {})
      if (params) req.params = params.parse(req.params ?? {})
      if (query) req.query = query.parse(req.query ?? {})
      next()
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ error: firstIssueMessage(err) })
      }
      next(err)
    }
  }
}

export const zIdParam = z.object({
  id: z.coerce.number().int().positive(),
})
