import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@openre/ui': path.resolve(__dirname, '../../packages/ui/src'),
      '@openre/api-client': path.resolve(__dirname, '../../packages/api-client/src'),
      '@openre/state': path.resolve(__dirname, '../../packages/state/src'),
      '@openre/utils': path.resolve(__dirname, '../../packages/utils/src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          query: ['@tanstack/react-query'],
          state: ['zustand'],
          ui: ['lucide-react', 'clsx', 'tailwind-merge'],
          editor: ['monaco-editor', '@monaco-editor/react'],
          flow: ['reactflow'],
        },
      },
    },
  },
});