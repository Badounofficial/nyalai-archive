import { defineConfig } from 'astro/config';

// Nyalai archive site configuration
// Deployed at archive.nyalai.com via Cloudflare Pages
// Zero third-party chrome commitment : no analytics, no fonts CDN, no external scripts

export default defineConfig({
  site: 'https://archive.nyalai.com',
  base: '/',
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
    assets: 'assets'
  },
  compressHTML: true,
  vite: {
    build: {
      cssMinify: true
    }
  }
});
