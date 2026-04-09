import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, '..')
const backendDir = path.join(root, 'backend')

const TARGET_EXT = new Set(['.js', '.mjs', '.cjs'])
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist'])

const RULES = [
  {
    id: 'no-err-message-in-api-response',
    description: 'Do not return raw exception messages in API responses.',
    regex: /res\.status\([^)]*\)\.json\(\{\s*error:\s*(err|e)\.message\b/g,
  },
  {
    id: 'no-stack-in-api-response',
    description: 'Do not return stack traces in API responses.',
    regex: /res\.status\([^)]*\)\.json\(\{[^}]*\bstack\s*:/g,
  },
  {
    id: 'no-raw-error-json-response',
    description: 'Do not return raw error objects in API responses.',
    regex: /res\.status\([^)]*\)\.json\(\{\s*error:\s*(err|e)\b/g,
  },
]

function walk(dir, out = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    if (IGNORE_DIRS.has(entry.name)) continue
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      walk(fullPath, out)
      continue
    }
    if (TARGET_EXT.has(path.extname(entry.name))) out.push(fullPath)
  }
  return out
}

function lineNumberAt(content, index) {
  let line = 1
  for (let i = 0; i < index; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1
  }
  return line
}

const files = walk(backendDir)
const violations = []

for (const filePath of files) {
  const content = fs.readFileSync(filePath, 'utf8')
  for (const rule of RULES) {
    rule.regex.lastIndex = 0
    let match
    while ((match = rule.regex.exec(content)) !== null) {
      violations.push({
        file: path.relative(root, filePath),
        line: lineNumberAt(content, match.index),
        rule: rule.id,
        description: rule.description,
        snippet: match[0],
      })
    }
  }
}

if (violations.length > 0) {
  console.error('[security-check] Unsafe API error response patterns detected:')
  for (const v of violations) {
    console.error(`- ${v.file}:${v.line} [${v.rule}] ${v.description}`)
    console.error(`  ${v.snippet}`)
  }
  process.exit(1)
}

console.log('[security-check] Safe error response checks passed.')
