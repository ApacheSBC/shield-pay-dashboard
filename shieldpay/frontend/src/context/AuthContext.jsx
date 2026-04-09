import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import client, { setAuthToken } from '../api/client.js'

const AuthContext = createContext(null)

const STORAGE_KEY = 'shieldpay_token'
const USER_KEY = 'shieldpay_user'

export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(() => localStorage.getItem(STORAGE_KEY))
  const [user, setUser] = useState(() => {
    try {
      const raw = localStorage.getItem(USER_KEY)
      return raw ? JSON.parse(raw) : null
    } catch {
      return null
    }
  })

  useEffect(() => {
    setAuthToken(token)
  }, [token])

  const login = async (email, password) => {
    const { data } = await client.post('/auth/login', { email, password })
    localStorage.setItem(STORAGE_KEY, data.token)
    localStorage.setItem(USER_KEY, JSON.stringify(data.user))
    setTokenState(data.token)
    setUser(data.user)
    return data.user
  }

  const register = async (payload) => {
    const { data } = await client.post('/auth/register', payload)
    localStorage.setItem(STORAGE_KEY, data.token)
    localStorage.setItem(USER_KEY, JSON.stringify(data.user))
    setTokenState(data.token)
    setUser(data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem(STORAGE_KEY)
    localStorage.removeItem(USER_KEY)
    setTokenState(null)
    setUser(null)
    setAuthToken(null)
  }

  const refreshMe = async () => {
    if (!token) return
    const { data } = await client.get('/auth/me')
    localStorage.setItem(USER_KEY, JSON.stringify(data.user))
    setUser(data.user)
  }

  const value = useMemo(
    () => ({
      token,
      user,
      login,
      register,
      logout,
      refreshMe,
      isAuthenticated: Boolean(token),
    }),
    [token, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth outside provider')
  return ctx
}
