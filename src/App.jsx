import { useState, useCallback, useRef } from 'react'
import { rsaDecrypt, aesDecrypt, aesGcmDecrypt, tryPrettyJson } from './crypto.js'
import styles from './App.module.css'

// ── tiny sub-components ──────────────────────────────────────────────────────

function Badge({ children, color = 'accent' }) {
  return <span className={`${styles.badge} ${styles['badge_' + color]}`}>{children}</span>
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button className={`${styles.iconBtn} ${copied ? styles.iconBtnCopied : ''}`} onClick={copy} title="Copy to clipboard">
      {copied
        ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      }
      <span>{copied ? 'Copied!' : 'Copy'}</span>
    </button>
  )
}

function StepBadge({ n, done }) {
  return (
    <div className={`${styles.stepBadge} ${done ? styles.stepDone : ''}`}>
      {done
        ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        : n
      }
    </div>
  )
}

function Field({ label, sublabel, children }) {
  return (
    <div className={styles.field}>
      <label className={styles.fieldLabel}>
        <span className={styles.labelDot} />
        {label}
        {sublabel && <span className={styles.sublabel}>{sublabel}</span>}
      </label>
      {children}
    </div>
  )
}

function ResultPanel({ title, value, isJson, isError }) {
  const [view, setView] = useState('raw')
  const json = isJson ? tryPrettyJson(value) : null

  return (
    <div className={`${styles.resultPanel} ${isError ? styles.resultError : styles.resultSuccess}`}>
      <div className={styles.resultHeader}>
        <div className={styles.resultTitle}>
          <span className={styles.resultDot} />
          {title}
        </div>
        <div className={styles.resultActions}>
          {json?.ok && (
            <div className={styles.viewToggle}>
              <button className={view === 'raw'    ? styles.active : ''} onClick={() => setView('raw')}>Raw</button>
              <button className={view === 'pretty' ? styles.active : ''} onClick={() => setView('pretty')}>JSON</button>
            </div>
          )}
          {!isError && <CopyButton text={view === 'pretty' && json?.ok ? json.pretty : value} />}
        </div>
      </div>
      <pre className={`${styles.resultPre} ${isError ? styles.preError : view === 'pretty' ? styles.preJson : ''}`}>
        {view === 'pretty' && json?.ok ? json.pretty : value}
      </pre>
      {!isError && json?.ok && view === 'pretty' && (
        <div className={styles.jsonMeta}>
          <span>✓ Valid JSON</span>
          <span>{Object.keys(json.parsed).length} top-level keys</span>
        </div>
      )}
    </div>
  )
}

// ── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  // Step 1 — RSA
  const [rsaEnc, setRsaEnc]   = useState('')
  const [rsaPvt, setRsaPvt]   = useState('')
  const [aesKey, setAesKey]   = useState('')
  const [rsaResult, setRsaResult] = useState(null)   // {text, error}
  const [rsaBusy, setRsaBusy] = useState(false)

  // Step 2 — AES
  const [aesPayload, setAesPayload] = useState('')
  const [aesMode,    setAesMode]    = useState('cbc-prefix') // cbc-prefix | cbc-hex-iv | gcm
  const [ivString,   setIvString]   = useState('')
  const [aesResult,  setAesResult]  = useState(null)
  const [aesBusy,    setAesBusy]    = useState(false)

  // ── RSA decrypt ────────────────────────────────────────────────────────────
  const doRsaDecrypt = useCallback(async () => {
    if (!rsaEnc.trim() || !rsaPvt.trim()) return
    setRsaBusy(true)
    setRsaResult(null)
    await new Promise(r => setTimeout(r, 200))
    try {
      const { text } = await rsaDecrypt(rsaEnc, rsaPvt)
      setAesKey(text)
      setRsaResult({ text, error: null })
    } catch (e) {
      let msg = e.message || String(e)
      if (msg.toLowerCase().includes('operation')) msg = 'Decryption failed — ciphertext does not match this private key, or wrong padding.'
      if (msg.toLowerCase().includes('import'))    msg = 'Invalid private key — ensure it is PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)'
      setRsaResult({ text: null, error: msg })
    }
    setRsaBusy(false)
  }, [rsaEnc, rsaPvt])

  // ── AES decrypt ────────────────────────────────────────────────────────────
  const doAesDecrypt = useCallback(async () => {
    if (!aesPayload.trim() || !aesKey.trim()) return
    setAesBusy(true)
    setAesResult(null)
    await new Promise(r => setTimeout(r, 200))
    try {
      let plain
      if (aesMode === 'gcm') {
        plain = await aesGcmDecrypt(aesPayload, aesKey)
      } else if (aesMode === 'cbc-hex-iv') {
        plain = await aesDecrypt(aesPayload, aesKey, { ivString })
      } else {
        // default: cbc, IV = first 16 bytes
        plain = await aesDecrypt(aesPayload, aesKey)
      }
      setAesResult({ text: plain, error: null })
    } catch (e) {
      setAesResult({ text: null, error: e.message || String(e) })
    }
    setAesBusy(false)
  }, [aesPayload, aesKey, aesMode, ivString])

  const step1Done = !!rsaResult?.text
  const step2Done = !!aesResult?.text

  return (
    <div className={styles.root}>
      {/* Background effects */}
      <div className={styles.gridBg} />
      <div className={styles.blob1} />
      <div className={styles.blob2} />
      <div className={styles.blob3} />

      <div className={styles.layout}>
        {/* Header */}
        <header className={styles.header}>
          <div className={styles.logoRow}>
            <div className={styles.logo}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                <circle cx="12" cy="16" r="1.2" fill="currentColor"/>
              </svg>
            </div>
            <span className={styles.logoText}>CryptoVault</span>
          </div>
          <h1 className={styles.headline}>
            RSA <span className={styles.arrow}>→</span> AES-256 <span className={styles.arrow}>→</span> Plaintext
          </h1>
          <p className={styles.sub}>Two-stage cryptographic decryption pipeline. Everything runs locally in your browser.</p>
          <div className={styles.pillRow}>
            <span className={styles.pill}>RSA-OAEP / SHA-256</span>
            <span className={styles.pill}>AES-256-CBC</span>
            <span className={styles.pill}>AES-256-GCM</span>
            <span className={styles.pill}>Web Crypto API</span>
          </div>
        </header>

        {/* Pipeline visual */}
        <div className={styles.pipeline}>
          {['RSA Ciphertext', 'AES-256 Key', 'Plaintext'].map((label, i) => (
            <div key={i} className={styles.pipeNode}>
              <div className={`${styles.pipeBox} ${i === 0 ? styles.pipeActive : i === 1 && step1Done ? styles.pipeActive : i === 2 && step2Done ? styles.pipeSuccess : ''}`}>
                <span className={styles.pipeLabel}>{label}</span>
              </div>
              {i < 2 && <div className={styles.pipeArrow}>
                <svg width="20" height="10" viewBox="0 0 20 10" fill="none">
                  <path d="M0 5h18M14 1l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>}
            </div>
          ))}
        </div>

        {/* ── STEP 1 ── */}
        <section className={styles.card}>
          <div className={styles.cardHeader}>
            <StepBadge n="1" done={step1Done} />
            <div>
              <h2 className={styles.cardTitle}>Decrypt RSA Ciphertext → AES Key</h2>
              <p className={styles.cardSub}>Uses RSA-OAEP with SHA-256 padding. Paste your Base64 ciphertext and PKCS#8 private key.</p>
            </div>
          </div>

          <div className={styles.twoCol}>
            <Field label="RSA Encrypted Value" sublabel="Base64">
              <textarea
                className={styles.textarea}
                rows={5}
                value={rsaEnc}
                onChange={e => setRsaEnc(e.target.value)}
                placeholder="bgz4lKIAxQVr0Fmh59NazAOvaphy…"
                spellCheck={false}
              />
            </Field>
            <Field label="RSA Private Key" sublabel="PEM / PKCS#8">
              <textarea
                className={styles.textarea}
                rows={5}
                value={rsaPvt}
                onChange={e => setRsaPvt(e.target.value)}
                placeholder={"-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n\n(also accepts VITE_APP_RSA_PVT_KEY = \"...\")"}
                spellCheck={false}
              />
            </Field>
          </div>

          <div className={styles.btnRow}>
            <button
              className={`${styles.btn} ${styles.btnPrimary} ${rsaBusy ? styles.btnBusy : ''}`}
              onClick={doRsaDecrypt}
              disabled={rsaBusy || !rsaEnc.trim() || !rsaPvt.trim()}
            >
              {rsaBusy
                ? <><div className={styles.spinner} /> Decrypting…</>
                : <><LockIcon /> Decrypt RSA → AES Key</>
              }
            </button>
          </div>

          {rsaResult && (
            <ResultPanel
              title={rsaResult.error ? 'RSA Decryption Failed' : 'Decrypted AES-256 Key'}
              value={rsaResult.error || rsaResult.text}
              isError={!!rsaResult.error}
              isJson={false}
            />
          )}
        </section>

        {/* connector */}
        <div className={styles.connector}>
          <div className={styles.connLine} />
          <div className={styles.connChip}>AES Key passed to Step 2</div>
          <div className={styles.connLine} />
        </div>

        {/* ── STEP 2 ── */}
        <section className={`${styles.card} ${!step1Done ? styles.cardDimmed : ''}`}>
          <div className={styles.cardHeader}>
            <StepBadge n="2" done={step2Done} />
            <div>
              <h2 className={styles.cardTitle}>Decrypt AES-256 Payload → Plaintext</h2>
              <p className={styles.cardSub}>Uses the AES key from Step 1. Supports CBC (IV-prefix or separate) and GCM modes.</p>
            </div>
          </div>

          {/* AES Key display / manual override */}
          <Field label="AES-256 Key" sublabel="auto-filled from Step 1, editable">
            <input
              className={styles.input}
              value={aesKey}
              onChange={e => setAesKey(e.target.value)}
              placeholder="32-character key string…"
              spellCheck={false}
            />
            {aesKey && (
              <div className={styles.keyMeta}>
                <span className={new TextEncoder().encode(aesKey).length === 32 ? styles.metaOk : styles.metaWarn}>
                  {new TextEncoder().encode(aesKey).length} / 32 bytes
                </span>
                {new TextEncoder().encode(aesKey).length === 32 && <span className={styles.metaOk}>✓ Valid AES-256 length</span>}
              </div>
            )}
          </Field>

          {/* Mode selector */}
          <div className={styles.modeRow}>
            <span className={styles.fieldLabel} style={{margin:0}}><span className={styles.labelDot} />AES Mode</span>
            <div className={styles.modeGroup}>
              {[
                { val: 'cbc-prefix', label: 'CBC (IV in payload)',  sub: 'First 16 bytes = IV' },
                { val: 'cbc-hex-iv', label: 'CBC (separate IV)',     sub: 'Text or 32-char hex' },
                { val: 'gcm',        label: 'GCM (IV in payload)',   sub: 'First 12 bytes = IV' },
              ].map(m => (
                <button
                  key={m.val}
                  className={`${styles.modeBtn} ${aesMode === m.val ? styles.modeBtnActive : ''}`}
                  onClick={() => setAesMode(m.val)}
                >
                  <span className={styles.modeBtnLabel}>{m.label}</span>
                  <span className={styles.modeBtnSub}>{m.sub}</span>
                </button>
              ))}
            </div>
          </div>

          {aesMode === 'cbc-hex-iv' && (
            <Field label="IV" sublabel="16-char text  OR  32-char hex string">
              <input
                className={styles.input}
                value={ivString}
                onChange={e => setIvString(e.target.value)}
                placeholder='e.g. ATLAS_API_PORTAL  or  000102030405060708090a0b0c0d0e0f'
                spellCheck={false}
              />
            </Field>
          )}

          <Field label="Encrypted Payload" sublabel="Base64">
            <textarea
              className={styles.textarea}
              rows={6}
              value={aesPayload}
              onChange={e => setAesPayload(e.target.value)}
              placeholder="Paste your Base64-encoded AES-encrypted payload here…"
              spellCheck={false}
            />
          </Field>

          <div className={styles.btnRow}>
            <button
              className={`${styles.btn} ${styles.btnSuccess} ${aesBusy ? styles.btnBusy : ''}`}
              onClick={doAesDecrypt}
              disabled={aesBusy || !aesPayload.trim() || !aesKey.trim()}
            >
              {aesBusy
                ? <><div className={styles.spinner} /> Decrypting…</>
                : <><KeyIcon /> Decrypt Payload → Plaintext</>
              }
            </button>
          </div>

          {aesResult && (
            <ResultPanel
              title={aesResult.error ? 'AES Decryption Failed' : 'Decrypted Payload'}
              value={aesResult.error || aesResult.text}
              isError={!!aesResult.error}
              isJson={!aesResult.error}
            />
          )}
        </section>

        {/* Footer */}
        <footer className={styles.footer}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          All cryptographic operations run entirely in your browser via the Web Crypto API.
          No keys, ciphertext, or plaintext ever leave your device.
        </footer>
      </div>
    </div>
  )
}

function LockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  )
}
function KeyIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="5.5"/>
      <path d="m21 2-9.6 9.6M15.5 7.5 19 11l2.5-2.5-3.5-3.5"/>
    </svg>
  )
}
