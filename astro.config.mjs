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
  },
});
