import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(async () => {
  const plugins = [react()];
  const major = Number((process.versions.node || '0').split('.')[0]);
  const disableChecker = process.env.VITE_DISABLE_CHECKER === 'true' || process.env.VITEST || major >= 22;

  if (!disableChecker) {
    const { default: checker } = await import('vite-plugin-checker');
    plugins.push(checker({ typescript: true }));
  }

  return {
    plugins,
    build: {
      target: 'esnext'
    },
  server: {
    port: 5173,
    host: '127.0.0.1',
  },
  resolve: {
    alias: {
      '@components': '/src/components',
      '@features': '/src/features',
      '@hooks': '/src/hooks',
      '@lib': '/src/lib',
      '@services': '/src/services',
      '@stores': '/src/stores',
      '@/types': '/src/types'
    }
    }
  };
});
