import net from 'net'
import { lookup as dnsLookup } from 'dns/promises'

const PRIVATE_HOST_RE = /^(localhost|localhost\.localdomain|.*\.local)$/i

export function normalizeHost(hostname) {
  const raw = String(hostname || '').trim().toLowerCase()
  if (!raw) return ''
  return raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw
}

function ipv4ToInt(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = (out << 8) | n
  }
  return out >>> 0
}

function isPrivateOrReservedIpv4Int(value) {
  const inRange = (base, maskBits) => {
    const shift = 32 - maskBits
    return (value >>> shift) === (base >>> shift)
  }
  return (
    inRange(0x00000000, 8) ||
    inRange(0x0a000000, 8) ||
    inRange(0x64400000, 10) ||
    inRange(0x7f000000, 8) ||
    inRange(0xa9fe0000, 16) ||
    inRange(0xac100000, 12) ||
    inRange(0xc0a80000, 16) ||
    inRange(0xc6120000, 15) ||
    inRange(0xe0000000, 4)
  )
}

function isPrivateOrReservedIpv4(ip) {
  const value = ipv4ToInt(ip)
  if (value == null) return false
  return isPrivateOrReservedIpv4Int(value)
}

function parseIpv4PartAutoBase(part) {
  const p = String(part || '').trim().toLowerCase()
  if (!p) return null
  if (/^0x[0-9a-f]+$/.test(p)) return Number.parseInt(p.slice(2), 16)
  if (/^0[0-7]+$/.test(p) && p.length > 1) return Number.parseInt(p.slice(1), 8)
  if (/^\d+$/.test(p)) return Number.parseInt(p, 10)
  return null
}

function parseIpv4AnyNotation(host) {
  const parts = String(host || '').split('.')
  if (parts.length < 1 || parts.length > 4) return null
  const parsed = parts.map((p) => parseIpv4PartAutoBase(p))
  if (parsed.some((n) => n == null || !Number.isFinite(n) || n < 0)) return null

  let value = 0
  if (parsed.length === 1) {
    if (parsed[0] > 0xffffffff) return null
    value = parsed[0]
  } else if (parsed.length === 2) {
    if (parsed[0] > 255 || parsed[1] > 0xffffff) return null
    value = (parsed[0] << 24) | parsed[1]
  } else if (parsed.length === 3) {
    if (parsed[0] > 255 || parsed[1] > 255 || parsed[2] > 0xffff) return null
    value = (parsed[0] << 24) | (parsed[1] << 16) | parsed[2]
  } else {
    if (parsed.some((n) => n > 255)) return null
    value = (parsed[0] << 24) | (parsed[1] << 16) | (parsed[2] << 8) | parsed[3]
  }
  return value >>> 0
}

function parseIpv6ToBigInt(ipv6Input) {
  let ip = String(ipv6Input || '').toLowerCase()
  if (!ip) return null
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':')
    if (lastColon <= -1) return null
    const v4 = ip.slice(lastColon + 1)
    const v4Int = ipv4ToInt(v4)
    if (v4Int == null) return null
    const hi = ((v4Int >>> 16) & 0xffff).toString(16)
    const lo = (v4Int & 0xffff).toString(16)
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`
  }
  const doubleColonCount = ip.split('::').length - 1
  if (doubleColonCount > 1) return null

  let groups = []
  if (ip.includes('::')) {
    const [left, right] = ip.split('::')
    const leftGroups = left ? left.split(':') : []
    const rightGroups = right ? right.split(':') : []
    const fill = 8 - (leftGroups.length + rightGroups.length)
    if (fill < 0) return null
    groups = [...leftGroups, ...Array(fill).fill('0'), ...rightGroups]
  } else {
    groups = ip.split(':')
    if (groups.length !== 8) return null
  }
  if (groups.length !== 8) return null

  let out = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
    out = (out << 16n) + BigInt(`0x${g}`)
  }
  return out
}

function isPrivateOrReservedIpv6(ip) {
  const value = parseIpv6ToBigInt(ip)
  if (value == null) return false
  const inRange = (baseHex, prefixBits) => {
    const base = BigInt(baseHex)
    const shift = 128n - BigInt(prefixBits)
    return (value >> shift) === (base >> shift)
  }
  if (value === 0n || value === 1n) return true
  if (inRange('0xfc000000000000000000000000000000', 7)) return true
  if (inRange('0xfe800000000000000000000000000000', 10)) return true
  if (inRange('0xff000000000000000000000000000000', 8)) return true
  if (inRange('0x00000000000000000000ffff00000000', 96)) {
    const mappedV4 = Number(value & 0xffffffffn)
    const v4 =
      `${(mappedV4 >>> 24) & 0xff}.${(mappedV4 >>> 16) & 0xff}.` +
      `${(mappedV4 >>> 8) & 0xff}.${mappedV4 & 0xff}`
    return isPrivateOrReservedIpv4(v4)
  }
  return false
}

export function parseWebhookAllowedHosts() {
  return new Set(
    String(process.env.WEBHOOK_ALLOWED_HOSTS || '')
      .split(',')
      .map((v) => normalizeHost(v))
      .filter(Boolean),
  )
}

function isHostnameAllowed(hostname, allowedHosts) {
  if (!allowedHosts || allowedHosts.size === 0) return true
  for (const allowed of allowedHosts) {
    if (hostname === allowed || hostname.endsWith(`.${allowed}`)) return true
  }
  return false
}

async function resolveHostnamePublic(hostname) {
  let records
  try {
    records = await dnsLookup(hostname, { all: true, verbatim: true })
  } catch {
    return false
  }
  if (!Array.isArray(records) || records.length === 0) return false
  for (const rec of records) {
    const addr = String(rec?.address || '')
    const family = Number(rec?.family || 0)
    if (family === 4 && isPrivateOrReservedIpv4(addr)) return false
    if (family === 6 && isPrivateOrReservedIpv6(addr)) return false
  }
  return true
}

export async function normalizeAndValidateWebhookUrl(input, allowedHosts = parseWebhookAllowedHosts()) {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null

  let parsed
  try {
    parsed = new URL(trimmed)
  } catch {
    return null
  }

  if (!['https:', 'http:'].includes(parsed.protocol)) return null
  if (!parsed.hostname) return null
  if (parsed.username || parsed.password) return null

  const hostname = normalizeHost(parsed.hostname)
  if (!hostname) return null
  if (PRIVATE_HOST_RE.test(hostname)) return null
  if (!isHostnameAllowed(hostname, allowedHosts)) return null

  const ipVersion = net.isIP(hostname)
  if (ipVersion === 4 && isPrivateOrReservedIpv4(hostname)) return null
  if (ipVersion === 6 && isPrivateOrReservedIpv6(hostname)) return null
  if (ipVersion === 0) {
    const exoticV4 = parseIpv4AnyNotation(hostname)
    if (exoticV4 != null && isPrivateOrReservedIpv4Int(exoticV4)) return null
    const dnsPublic = await resolveHostnamePublic(hostname)
    if (!dnsPublic) return null
  }

  parsed.hash = ''
  return parsed.toString()
}
