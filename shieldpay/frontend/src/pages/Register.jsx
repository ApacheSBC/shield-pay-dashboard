import React, { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { safeErrorMessage } from '../utils/safeErrorMessage.js'

export default function Register() {
  const { register, isAuthenticated } = useAuth()
  const nav = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [merchantName, setMerchantName] = useState('')
  const [err, setErr] = useState('')

  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  const submit = async (e) => {
    e.preventDefault()
    setErr('')
    try {
      await register({ email, password, merchantName })
      nav('/', { replace: true })
    } catch (ex) {
      setErr(safeErrorMessage(ex.response?.data?.error, 'Registration failed'))
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Register</h1>
        <p className="sub">New merchant workspace</p>
        <form onSubmit={submit}>
          <div className="form-group">
            <label htmlFor="m">Business name</label>
            <input id="m" value={merchantName} onChange={(e) => setMerchantName(e.target.value)} required />
          </div>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {err && <p className="error-msg">{err}</p>}
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
            Create account
          </button>
        </form>
        <p style={{ marginTop: '1rem' }}>
          <Link to="/login">Back to login</Link>
        </p>
      </div>
    </div>
  )
}
