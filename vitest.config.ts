import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    server: {
      deps: {
        // cloudflare:sockets and @cloudflare/puppeteer are Worker-only runtime
        // modules; the raw TLS peer fast path imports them. For unit tests we
        // stub them out so report-builder / mcp tests can import without blowup.
        inline: [/cloudflare:sockets/, /@cloudflare\/puppeteer/],
      },
    },
  },
  resolve: {
    alias: {
      '@': '/src',
      '@lib': '/src/lib',
      'cloudflare:sockets': '/tests/stubs/cloudflare-sockets.ts',
      '@cloudflare/puppeteer': '/tests/stubs/cloudflare-puppeteer.ts',
    },
  },
});
