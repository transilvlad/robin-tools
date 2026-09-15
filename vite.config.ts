import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { federation } from '@module-federation/vite';

const appPort = 4175;
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

// Node >=25 exposes a native `localStorage` global that jsdom defers to instead of its
// own implementation; without --localstorage-file it's a no-op that returns undefined,
// breaking jsdom's `window.localStorage` in tests. --no-webstorage removes the native
// global entirely so jsdom falls back to its own working implementation. The flag
// doesn't exist before Node 25, so it's only added when actually supported.
const nodeMajor = Number(process.versions.node.split('.')[0]);
const testExecArgv = nodeMajor >= 25 ? ['--no-webstorage'] : [];

export default defineConfig({
  cacheDir: '.vite',
  base: '/modules/robin-tools/',
  plugins: [
    react(),
    federation({
      name: 'robinTools',
      filename: 'remoteEntry.js',
      exposes: {
        './RobinToolsApp': './src/remote.tsx',
      },
      dts: false,
      shared: {
        react: {
          singleton: true,
          requiredVersion: '^19.3.0',
        },
        'react-dom': {
          singleton: true,
          requiredVersion: '^19.3.0',
        },
      },
    }),
  ],
  server: {
    host: '0.0.0.0',
    port: appPort,
    strictPort: true,
    cors: true,
    origin: `http://localhost:${appPort}`,
    headers: corsHeaders,
  },
  preview: {
    host: '0.0.0.0',
    port: appPort,
    strictPort: true,
    cors: true,
    headers: corsHeaders,
  },
  build: {
    target: 'esnext',
    modulePreload: false,
    cssCodeSplit: false,
  },
  test: {
    execArgv: testExecArgv,
  },
});
