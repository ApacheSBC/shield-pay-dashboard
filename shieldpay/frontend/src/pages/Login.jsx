import React, { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Login() {
  const { login, isAuthenticated } = useAuth()
  const nav = useNavigate()
  const [email, setEmail] = useState('merchant@demo.com')
  const [password, setPassword] = useState('Demo1234!')
  const [err, setErr] = useState('')

  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    try {
      await login(email, password)
      nav('/', { replace: true })
    } catch {
      setErr('Login failed. Check email and password.')
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>ShieldPay</h1>
        <p className="sub">Multi-merchant dashboard (demo / fake money)</p>
        <form onSubmit={submit}>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input id="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>
          {err && <p className="error-msg">{err}</p>}
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
            Sign in
          </button>
        </form>
        <p style={{ marginTop: '1rem', color: 'var(--muted)', fontSize: '0.9rem' }}>
          Demo merchant: merchant@demo.com / Demo1234!
        </p>
        <p style={{ marginTop: '0.5rem' }}>
          <Link to="/register">Create merchant account</Link>
        </p>
      </div>
    </div>
  )
}
