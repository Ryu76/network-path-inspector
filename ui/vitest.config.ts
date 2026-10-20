import { defineConfig } from 'vitest/config';

// Vitest jsdom 테스트 환경 설정 (중앙 계약 상위 디렉터리 상대 경로 접근만 허용)
export default defineConfig({
  server: {
    fs: {
      strict: true,
      allow: ['..'],
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.{ts,tsx}'],
    globals: false,
  },
});
