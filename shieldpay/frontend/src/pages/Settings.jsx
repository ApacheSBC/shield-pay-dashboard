import React, { useEffect, useState } from 'react'
import client from '../api/client.js'
import { safeDisplayText } from '../utils/safeDisplayText.js'

export default function Settings() {
  const [profile, setProfile] = useState(null)
  const [keys, setKeys] = useState([])
  const [hooks, setHooks] = useState([])
  const [merchantName, setMerchantName] = useState('')
  const [newKeyLabel, setNewKeyLabel] = useState('')
  const [hookUrl, setHookUrl] = useState('https://example.com/hook')
  const [exportJson, setExportJson] = useState('')
  const [msg, setMsg] = useState('')
  const [ephemeralSecret, setEphemeralSecret] = useState('')
  const [secretVisibleUntil, setSecretVisibleUntil] = useState(0)
  const [secretNowMs, setSecretNowMs] = useState(0)

  const load = () => {
    client.get('/settings/profile').then((r) => {
      setProfile(r.data.profile)
      setMerchantName(r.data.profile.merchant_name || '')
    })
    client.get('/settings/api-keys').then((r) => setKeys(r.data.keys))
    client.get('/settings/webhooks').then((r) => setHooks(r.data.webhooks))
  }

  useEffect(() => {
    load()
  }, [])

  const saveProfile = async (e) => {
    e.preventDefault()
    setMsg('')
    await client.patch('/settings/profile', { merchantName })
    setMsg('Profile saved')
    load()
  }

  const createKey = async (e) => {
    e.preventDefault()
    setMsg('')
    const { data } = await client.post('/settings/api-keys', { label: newKeyLabel })
    setEphemeralSecret(data.secret)
    setSecretVisibleUntil(Date.now() + 30000)
    setNewKeyLabel('')
    load()
  }

  useEffect(() => {
    if (!ephemeralSecret) return
    setSecretNowMs(Date.now())
    const timeout = setTimeout(() => {
      setEphemeralSecret('')
      setSecretVisibleUntil(0)
    }, 30000)
    const interval = setInterval(() => {
      setSecretNowMs(Date.now())
    }, 1000)
    return () => {
      clearTimeout(timeout)
      clearInterval(interval)
    }
  }, [ephemeralSecret])

  const addHook = async (e) => {
    e.preventDefault()
    await client.post('/settings/webhooks', { url: hookUrl, secret: 'demo' })
    load()
  }

  const runExport = async () => {
    const { data } = await client.get('/settings/export')
    setExportJson(JSON.stringify(data, null, 2))
  }

  if (!profile) return <p style={{ color: 'var(--muted)' }}>Loading…</p>

  return (
    <>
      <h1>Settings</h1>

      <div className="card">
        <h2>Profile</h2>
        <form onSubmit={saveProfile}>
          <div className="form-group">
            <label htmlFor="biz">Business name</label>
            <input id="biz" value={merchantName} onChange={(e) => setMerchantName(e.target.value)} />
          </div>
          <button type="submit" className="btn btn-primary">
            Save
          </button>
        </form>
      </div>

      <div className="card">
        <h2>API keys</h2>
        <ul style={{ color: 'var(--muted)', paddingLeft: '1.2rem' }}>
          {keys.map((k) => (
            <li key={k.id}>
              {safeDisplayText(k.label)} — {k.key_prefix}… ({k.created_at})
            </li>
          ))}
        </ul>
        <form onSubmit={createKey} style={{ marginTop: '1rem' }}>
          <div className="form-group">
            <label htmlFor="kl">Label</label>
            <input id="kl" value={newKeyLabel} onChange={(e) => setNewKeyLabel(e.target.value)} placeholder="Production" />
          </div>
          <button type="submit" className="btn btn-ghost">
            Create key
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Webhooks</h2>
        <ul style={{ color: 'var(--muted)', paddingLeft: '1.2rem' }}>
          {hooks.map((h) => (
            <li key={h.id}>
              {safeDisplayText(h.url)} {h.active ? '(active)' : ''}
            </li>
          ))}
        </ul>
        <form onSubmit={addHook} style={{ marginTop: '1rem' }}>
          <div className="form-group">
            <label htmlFor="url">URL</label>
            <input id="url" value={hookUrl} onChange={(e) => setHookUrl(e.target.value)} />
          </div>
          <button type="submit" className="btn btn-ghost">
            Add webhook
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Export (unsafe in baseline)</h2>
        <button type="button" className="btn btn-primary" onClick={runExport}>
          Download JSON snapshot
        </button>
        {exportJson && (
          <pre className="mono" style={{ marginTop: '1rem', maxHeight: '320px', overflow: 'auto', whiteSpace: 'pre-wrap' }}>
            {exportJson}
          </pre>
        )}
      </div>

      {msg && <p className="pill" style={{ display: 'inline-block', marginTop: '0.5rem' }}>{msg}</p>}
      {ephemeralSecret && (
        <div
          className="card"
          role="dialog"
          aria-live="polite"
          style={{
            position: 'fixed',
            right: '1rem',
            bottom: '1rem',
            maxWidth: '520px',
            zIndex: 1000,
            borderColor: 'var(--accent)',
          }}
        >
          <h2 style={{ marginBottom: '0.5rem' }}>New API key (one-time reveal)</h2>
          <p style={{ color: 'var(--muted)' }}>
            Copy this key now. It auto-clears in {Math.max(1, Math.ceil((secretVisibleUntil - secretNowMs) / 1000))}s.
          </p>
          <div
            className="mono"
            style={{
              margin: '0.5rem 0',
              padding: '0.65rem',
              borderRadius: '8px',
              border: '1px solid var(--border)',
              background: 'var(--bg)',
            }}
          >
            {ephemeralSecret}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(ephemeralSecret)
                  setMsg('API key copied to clipboard')
                } catch {
                  setMsg('Copy failed. Copy manually before it clears.')
                }
              }}
            >
              Copy
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                setEphemeralSecret('')
                setSecretVisibleUntil(0)
              }}
            >
              Clear now
            </button>
          </div>
        </div>
      )}
    </>
  )
}
