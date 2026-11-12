import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['server/test/**/*.test.ts', 'client/src/**/*.test.ts'],
    clearMocks: true,
  },
});
