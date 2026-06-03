import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
      '/saml': {
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../internal/ui/dist',
    emptyOutDir: true,
  },
});
