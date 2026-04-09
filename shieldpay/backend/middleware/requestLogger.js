// ARKO-LAB-05: sensitive request logging — logs passwords and payment fields to the console.

export function requestBodyLogger(req, res, next) {
  if (req.path.startsWith('/api') && req.method !== 'GET' && req.body && Object.keys(req.body).length) {
    console.log('[ShieldPay dev log]', req.method, req.path, JSON.stringify(req.body))
  }
  next()
}
