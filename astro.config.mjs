import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://netlens.pages.dev',
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
  },
});
