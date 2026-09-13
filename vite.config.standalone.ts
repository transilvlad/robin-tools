import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Standalone build: a plain, self-contained SPA (no module federation, no
// host-relative base path) served directly by the Express backend in
// DEPLOYMENT_MODE=standalone. See server/src/index.ts.
export default defineConfig({
  cacheDir: '.vite-standalone',
  base: '/',
  plugins: [react()],
  build: {
    target: 'esnext',
    outDir: 'dist-standalone',
    emptyOutDir: true,
  },
});
