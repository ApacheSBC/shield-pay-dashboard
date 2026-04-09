import axios from 'axios'

const client = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

if (typeof window !== 'undefined') {
  const existing = localStorage.getItem('shieldpay_token')
  if (existing) {
    client.defaults.headers.common.Authorization = `Bearer ${existing}`
  }
}

export function setAuthToken(token) {
  if (token) {
    client.defaults.headers.common.Authorization = `Bearer ${token}`
  } else {
    delete client.defaults.headers.common.Authorization
  }
}

export default client
