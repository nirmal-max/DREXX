import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The console is served as static files from any web server, and from
// `python -m http.server` during a demo, so the build stays dependency-free at
// runtime: no API calls, no CDN, every hash recomputed in the browser.
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    sourcemap: false,
    minify: true,
  },
})
