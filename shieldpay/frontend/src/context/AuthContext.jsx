import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import client from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  const login = async (email, password) => {
    const { data } = await client.post('/auth/login', { email, password })
    setUser(data.user)
    return data.user
  }

  const register = async (payload) => {
    const { data } = await client.post('/auth/register', payload)
    setUser(data.user)
    return data.user
  }

  const logout = async () => {
    try {
      await client.post('/auth/logout')
    } catch {
      // ignore logout network errors; clear local state regardless
    }
    setUser(null)
  }

  const refreshMe = async () => {
    try {
      const { data } = await client.get('/auth/me')
      setUser(data.user)
    } catch {
      setUser(null)
    } finally {
      setReady(true)
    }
  }

  useEffect(() => {
    refreshMe()
  }, [])

  const value = useMemo(
    () => ({
      user,
      ready,
      login,
      register,
      logout,
      refreshMe,
      isAuthenticated: Boolean(user),
    }),
    [user, ready],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth outside provider')
  return ctx
}
