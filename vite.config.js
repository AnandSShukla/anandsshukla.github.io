import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ✏️  Change '/crypto-vault/' to match your IIS application / virtual directory name.
//     Must start AND end with a slash.  e.g.  '/tools/crypto-vault/'
// const BASE_PATH = '/crypto-vault/'

export default defineConfig({
  plugins: [react()],
  base: "/",
})
