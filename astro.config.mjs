import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://netrecon.pages.dev',
  output: 'static',
  build: {
    assets: 'assets',
  },
  vite: {
    resolve: {
      alias: {
        '@': '/src',
        '@lib': '/src/lib',
      },
    },
    build: {
      rollupOptions: {
        // Workers-only runtime modules. These are available inside Pages
        // Functions at runtime but not at static build time. report-builder
        // dynamic-imports tls-peer, so during SSG no top-level code reaches
        // these — but Rollup still needs them externalized so the lazy chunk
        // can be emitted without resolution errors.
        external: ['cloudflare:sockets', '@cloudflare/puppeteer'],
      },
    },
    ssr: {
      external: ['cloudflare:sockets', '@cloudflare/puppeteer'],
    },
  },
});
