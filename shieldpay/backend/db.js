import Database from 'better-sqlite3'
import bcrypt from 'bcrypt'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { encryptField } from './crypto/cardFieldCrypto.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

let dbInstance = null

export function getDb() {
  if (!dbInstance) throw new Error('Database not initialized')
  return dbInstance
}

export async function initDb() {
  const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'shieldpay.db')
  const dir = path.dirname(dbPath)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }

  dbInstance = new Database(dbPath)
  dbInstance.pragma('journal_mode = WAL')

  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','merchant')),
      merchant_name TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS merchant_api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      label TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      secret TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `)

  ensureCardsTable(dbInstance)
  ensureTransactionsTable(dbInstance)

  await seedIfNeeded()
}

function tableExists(db, name) {
  return Boolean(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(name))
}

/** PAN/CVV at rest: AES-256-GCM ciphertext in pan_encrypted / cvv_encrypted (see CARD_ENCRYPTION_KEY). */
function ensureCardsTable(db) {
  if (!tableExists(db, 'cards')) {
    db.exec(`
      CREATE TABLE cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        pan_encrypted TEXT NOT NULL,
        cvv_encrypted TEXT NOT NULL,
        brand TEXT,
        exp_month INTEGER,
        exp_year INTEGER,
        label TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `)
    return
  }

  const cols = db.prepare('PRAGMA table_info(cards)').all()
  const names = new Set(cols.map((c) => c.name))
  if (names.has('pan_encrypted')) return
  if (names.has('pan_plain')) {
    migrateCardsPlainToEncrypted(db)
  }
}

function migrateCardsPlainToEncrypted(db) {
  const rows = db.prepare('SELECT * FROM cards').all()
  db.pragma('foreign_keys = OFF')
  db.exec('BEGIN')
  try {
    db.exec(`
      CREATE TABLE cards_migrated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        pan_encrypted TEXT NOT NULL,
        cvv_encrypted TEXT NOT NULL,
        brand TEXT,
        exp_month INTEGER,
        exp_year INTEGER,
        label TEXT,
        created_at TEXT NOT NULL
      );
    `)
    const ins = db.prepare(`
      INSERT INTO cards_migrated (id, customer_id, merchant_id, pan_encrypted, cvv_encrypted, brand, exp_month, exp_year, label, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    for (const r of rows) {
      ins.run(
        r.id,
        r.customer_id,
        r.merchant_id,
        encryptField(String(r.pan_plain)),
        encryptField(String(r.cvv_plain)),
        r.brand,
        r.exp_month,
        r.exp_year,
        r.label,
        r.created_at,
      )
    }
    db.exec('DROP TABLE cards')
    db.exec('ALTER TABLE cards_migrated RENAME TO cards')
    db.exec('COMMIT')
  } catch (e) {
    db.exec('ROLLBACK')
    throw e
  } finally {
    db.pragma('foreign_keys = ON')
  }
}

function ensureTransactionsTable(db) {
  if (!tableExists(db, 'transactions')) {
    db.exec(`
      CREATE TABLE transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        merchant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
        card_id INTEGER REFERENCES cards(id) ON DELETE SET NULL,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        status TEXT NOT NULL,
        description TEXT,
        pan_snapshot_encrypted TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `)
    return
  }

  const cols = db.prepare('PRAGMA table_info(transactions)').all()
  const names = new Set(cols.map((c) => c.name))

  if (!names.has('pan_snapshot_encrypted')) {
    db.exec('ALTER TABLE transactions ADD COLUMN pan_snapshot_encrypted TEXT')
  }

  if (names.has('pan_snapshot_plain')) {
    const rows = db
      .prepare(
        `SELECT id, pan_snapshot_plain FROM transactions WHERE pan_snapshot_plain IS NOT NULL AND pan_snapshot_plain != ''`,
      )
      .all()
    const upd = db.prepare(
      'UPDATE transactions SET pan_snapshot_encrypted = ?, pan_snapshot_plain = NULL WHERE id = ?',
    )
    for (const r of rows) {
      upd.run(encryptField(String(r.pan_snapshot_plain)), r.id)
    }
    try {
      db.exec('ALTER TABLE transactions DROP COLUMN pan_snapshot_plain')
    } catch {
      /* SQLite < 3.35 or busy; column left unused */
    }
  }
}

async function seedIfNeeded() {
  const count = getDb().prepare('SELECT COUNT(*) AS c FROM users').get().c
  if (count > 0) return

  const adminEmail = process.env.ADMIN_EMAIL || 'admin@shieldpay.lab'
  const adminPassword = process.env.ADMIN_PASSWORD || 'ChangeMeAdmin123!'
  const adminHash = await bcrypt.hash(adminPassword, 10)

  getDb()
    .prepare(
      `INSERT INTO users (email, password_hash, role, merchant_name) VALUES (?, ?, 'admin', NULL)`,
    )
    .run(adminEmail, adminHash)

  const demoHash = await bcrypt.hash('Demo1234!', 10)
  const demoResult = getDb()
    .prepare(
      `INSERT INTO users (email, password_hash, role, merchant_name) VALUES (?, ?, 'merchant', ?)`,
    )
    .run('merchant@demo.com', demoHash, 'Demo Merchant Co.')

  const merchantId = demoResult.lastInsertRowid

  const c1 = getDb()
    .prepare(
      `INSERT INTO customers (merchant_id, name, email, phone, notes) VALUES (?, ?, ?, ?, ?)`,
    )
    .run(merchantId, 'Alex Tester', 'alex@test.lab', '555-0100', 'VIP')

  const c1Id = c1.lastInsertRowid

  const c2 = getDb()
    .prepare(
      `INSERT INTO customers (merchant_id, name, email, phone, notes) VALUES (?, ?, ?, ?, ?)`,
    )
    .run(merchantId, 'Jamie Sample', 'jamie@test.lab', '555-0200', 'New lead')

  const c2Id = c2.lastInsertRowid

  const insCard = getDb().prepare(
    `INSERT INTO cards (customer_id, merchant_id, pan_encrypted, cvv_encrypted, brand, exp_month, exp_year, label)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
  const card1 = insCard.run(
    c1Id,
    merchantId,
    encryptField('4111111111111111'),
    encryptField('123'),
    'visa',
    12,
    2030,
    'Work card',
  )
  const card1Id = card1.lastInsertRowid

  const card2 = insCard.run(
    c2Id,
    merchantId,
    encryptField('4242424242424242'),
    encryptField('456'),
    'visa',
    6,
    2029,
    'Personal',
  )
  const card2Id = card2.lastInsertRowid

  getDb()
    .prepare(
      `INSERT INTO transactions (merchant_id, customer_id, card_id, amount_cents, currency, status, description, pan_snapshot_encrypted)
       VALUES (?, ?, ?, ?, 'USD', ?, ?, ?)`,
    )
    .run(merchantId, c1Id, card1Id, 2500, 'captured', 'Coffee subscription', encryptField('4111111111111111'))

  getDb()
    .prepare(
      `INSERT INTO transactions (merchant_id, customer_id, card_id, amount_cents, currency, status, description, pan_snapshot_encrypted)
       VALUES (?, ?, ?, ?, 'USD', ?, ?, ?)`,
    )
    .run(merchantId, c2Id, card2Id, 8900, 'pending', 'Hardware order', encryptField('4242424242424242'))

  const sk = await bcrypt.hash('sk_demo_' + merchantId, 8)
  getDb()
    .prepare(
      `INSERT INTO merchant_api_keys (merchant_id, key_prefix, key_hash, label) VALUES (?, ?, ?, ?)`,
    )
    .run(merchantId, 'sk_demo_', sk, 'Default key')

  getDb()
    .prepare(`INSERT INTO webhooks (merchant_id, url, secret, active) VALUES (?, ?, ?, 1)`)
    .run(merchantId, 'https://example.com/webhook', 'whsec_demo_only')
}
