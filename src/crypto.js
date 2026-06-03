// ─── Helpers ────────────────────────────────────────────────────────────────

export function base64ToUint8Array(b64) {
  const clean  = b64.replace(/\s+/g, '')
  const binary = atob(clean)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function uint8ArrayToBase64(bytes) {
  let binary = ''
  bytes.forEach(b => (binary += String.fromCharCode(b)))
  return btoa(binary)
}

function cleanPem(raw) {
  let pem = raw.trim()
  // Handle VITE_APP_RSA_PVT_KEY = "..." wrapper
  const envMatch = pem.match(/=\s*["']?(-----BEGIN[\s\S]+-----END[^-]+-----)["']?/)
  if (envMatch) pem = envMatch[1]
  // Normalise line breaks around header / footer
  pem = pem
    .replace(/-----BEGIN PRIVATE KEY-----\s*/g, '-----BEGIN PRIVATE KEY-----\n')
    .replace(/\s*-----END PRIVATE KEY-----/g,   '\n-----END PRIVATE KEY-----')
    .replace(/\n{2,}/g, '\n')
    .trim()
  return pem
}

// ─── RSA-OAEP Decrypt ───────────────────────────────────────────────────────

export async function rsaDecrypt(encryptedB64, pemRaw) {
  const pem     = cleanPem(pemRaw)
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '')

  const keyBytes   = base64ToUint8Array(pemBody)
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    keyBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  )

  const cipherBytes = base64ToUint8Array(encryptedB64)
  const plainBytes  = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    cipherBytes
  )

  return {
    text:  new TextDecoder().decode(plainBytes),
    bytes: new Uint8Array(plainBytes),
  }
}

// ─── AES-256-CBC Decrypt ────────────────────────────────────────────────────

/**
 * Parse an IV from user input.
 * Accepts three formats (auto-detected):
 *   1. 32-char hex string  → decoded as hex bytes        (e.g. "0102030405...")
 *   2. Plain text string   → encoded as UTF-8 bytes      (e.g. "ATLAS_API_PORTAL")
 *   3. Base64 string       → decoded as base64 bytes     (passed explicitly)
 * The IV must resolve to exactly 16 bytes.
 */
function parseIV(ivInput) {
  const trimmed = ivInput.trim()

  // Looks like a pure hex string (even length, only 0-9 a-f)?
  const isHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0

  if (isHex && trimmed.length === 32) {
    // 32 hex chars = 16 bytes — classic hex IV
    return hexToUint8Array(trimmed)
  }

  // Otherwise treat as a plain UTF-8 string (e.g. "ATLAS_API_PORTAL")
  const encoded = new TextEncoder().encode(trimmed)
  if (encoded.length === 16) {
    return encoded
  }

  // If still wrong length, throw a helpful error
  throw new Error(
    `IV must be exactly 16 bytes. ` +
    `"${trimmed}" encodes to ${encoded.length} byte(s) as UTF-8. ` +
    `For text IVs use exactly 16 ASCII characters. ` +
    `For hex IVs use exactly 32 hex characters.`
  )
}

export async function aesDecrypt(encryptedB64, aesKeyStr, { ivString, ivB64, ivPrefix } = {}) {
  // Encode key string → raw bytes (UTF-8), must be 32 bytes for AES-256
  const keyBytes = new TextEncoder().encode(aesKeyStr)
  if (keyBytes.length !== 32) {
    throw new Error(
      `AES key must be exactly 32 bytes (256 bits). Got ${keyBytes.length} bytes — ` +
      `"${aesKeyStr}" is ${keyBytes.length} chars (assuming ASCII).`
    )
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  )

  let iv
  let cipherPayload

  if (ivString) {
    // User-supplied IV: auto-detect hex vs plain text
    iv = parseIV(ivString)
    cipherPayload = base64ToUint8Array(encryptedB64)
  } else if (ivB64) {
    iv = base64ToUint8Array(ivB64)
    cipherPayload = base64ToUint8Array(encryptedB64)
  } else {
    // Default: first 16 bytes of decoded ciphertext are the IV (common pattern)
    const full = base64ToUint8Array(encryptedB64)
    iv            = full.slice(0, 16)
    cipherPayload = full.slice(16)
  }

  const plainBytes = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    cipherPayload
  )

  return new TextDecoder().decode(plainBytes)
}

// ─── AES-256-GCM Decrypt ────────────────────────────────────────────────────

export async function aesGcmDecrypt(encryptedB64, aesKeyStr) {
  const keyBytes = new TextEncoder().encode(aesKeyStr)
  if (keyBytes.length !== 32) {
    throw new Error(`AES key must be exactly 32 bytes. Got ${keyBytes.length}.`)
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )

  const full = base64ToUint8Array(encryptedB64)
  // GCM standard: first 12 bytes = IV/nonce
  const iv            = full.slice(0, 12)
  const cipherPayload = full.slice(12)

  const plainBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    cipherPayload
  )

  return new TextDecoder().decode(plainBytes)
}

// ─── Utils ───────────────────────────────────────────────────────────────────

function hexToUint8Array(hex) {
  const clean = hex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function tryPrettyJson(text) {
  try {
    const parsed = JSON.parse(text)
    return { ok: true, pretty: JSON.stringify(parsed, null, 2), parsed }
  } catch {
    return { ok: false, pretty: null, parsed: null }
  }
}
