import { defineConfig } from 'vite';

// 중앙 계약 JSON(../contracts/g1-interface-contract.json)만 읽을 수 있도록
// 워크스페이스 상위 디렉터리(..)까지만 제한적으로 파일 접근을 허용합니다.
export default defineConfig({
  server: {
    fs: {
      strict: true,
      allow: ['..'],
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
