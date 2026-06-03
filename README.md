# CryptoVault — RSA + AES-256 Decryptor

A two-stage cryptographic decryption tool that runs entirely in the browser.  
**RSA-OAEP ciphertext → AES-256 key → Plaintext / Pretty JSON**

---

## 🚀 Local Development

```bash
npm install
npm run dev
```

Open http://localhost:5173

---

## 🌐 Deploy to Netlify (Free)

### Option A — Netlify CLI (fastest, ~2 min)

```bash
# 1. Install Netlify CLI globally
npm install -g netlify-cli

# 2. Build the project
npm run build

# 3. Login to Netlify (opens browser)
netlify login

# 4. Deploy (follow prompts — choose "dist" as publish dir)
netlify deploy --prod --dir=dist
```

Your app is live at a URL like: `https://your-site-name.netlify.app`

---

### Option B — Netlify Drop (zero setup, no account needed)

1. Run `npm run build` — this creates a `dist/` folder
2. Go to **https://app.netlify.com/drop**
3. Drag and drop the entire `dist/` folder onto the page
4. Done! Netlify gives you a live URL instantly.

---

### Option C — GitHub + Netlify (auto-deploys on push)

1. Push this project to a GitHub repo
2. Go to **https://app.netlify.com** → "Add new site" → "Import an existing project"
3. Connect your GitHub account and select the repo
4. Set build settings:
   - **Build command:** `npm run build`
   - **Publish directory:** `dist`
5. Click "Deploy site"

Every `git push` to `main` will auto-redeploy. ✓

---

### Option D — Vercel (alternative free host)

```bash
npm install -g vercel
npm run build
vercel --prod
```

Or connect your GitHub repo at **https://vercel.com/new**

---

## 🔐 How It Works

| Step | Operation | Algorithm |
|------|-----------|-----------|
| 1 | Decrypt RSA ciphertext → AES-256 key | RSA-OAEP / SHA-256 |
| 2a | Decrypt AES payload (IV in payload) | AES-256-CBC, first 16 bytes = IV |
| 2b | Decrypt AES payload (separate IV) | AES-256-CBC, IV provided as hex |
| 2c | Decrypt AES payload (GCM mode) | AES-256-GCM, first 12 bytes = nonce |

All operations use the browser's native **Web Crypto API** — no third-party crypto libraries.  
No data ever leaves your browser.

---

## 📁 Project Structure

```
crypto-tool/
├── index.html
├── vite.config.js
├── package.json
├── netlify.toml        ← SPA routing config
└── src/
    ├── main.jsx
    ├── index.css
    ├── App.jsx         ← Main UI (all 3 steps)
    ├── App.module.css  ← Scoped styles
    └── crypto.js       ← RSA + AES Web Crypto utilities
```
