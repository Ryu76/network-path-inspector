#!/usr/bin/env node
/**
 * NPI G1 UI 정적 가드 린트 (guardlint)
 *
 * 주의: 이 스크립트는 ESLint가 아니며, G1 안전 규칙 및 코드 무결성을 검증하는
 * 결정론적 정적 규칙 검사기(guardlint)입니다. 추후 부모 통합 단계에서 ESLint가 추가될 수 있습니다.
 *
 * 검사 항목:
 * 1. TypeScript/린트 우회 주석 금지 (@ts-ignore, @ts-nocheck, @ts-expect-error, eslint-disable)
 * 2. G1 UI 코드 내 네트워크/소켓/프로브/하위 프로세스 API 호출 금지 (fetch, WebSocket, XMLHttpRequest 등)
 * 3. 미승인 Tauri IPC/권한/동적 코드 실행 발명 금지 (__TAURI__, @tauri-apps/, eval, new Function)
 * 4. 금지된 타 프로젝트명(LibMate, SeatMate) 및 예시 192.168.* 대역 하드코딩 금지
 * 5. 중앙 계약(g1-interface-contract.json) 기능 목록 복제 금지
 * 6. UTF-8 BOM 금지, 줄 끝 공백(trailing whitespace) 금지, 파일 마지막 개행(\n) 필수
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SUPPRESSION_PATTERNS = [
  { id: 'NO_TS_IGNORE', token: '@ts-' + 'ignore', label: 'TypeScript @ts-ignore 우회 금지' },
  { id: 'NO_TS_NOCHECK', token: '@ts-' + 'nocheck', label: 'TypeScript @ts-nocheck 우회 금지' },
  { id: 'NO_TS_EXPECT_ERROR', token: '@ts-' + 'expect-error', label: 'TypeScript @ts-expect-error 우회 금지' },
  { id: 'NO_ESLINT_DISABLE', token: 'eslint-' + 'disable', label: 'eslint-disable 우회 금지' },
];

const FORBIDDEN_RUNTIME_PATTERNS = [
  { id: 'NO_FETCH', regex: /\bfetch\s*\(/, label: 'G1 UI에서 네트워크 fetch() 호출 금지' },
  { id: 'NO_XHR', regex: /\bXMLHttpRequest\b/, label: 'G1 UI에서 XMLHttpRequest 사용 금지' },
  { id: 'NO_WEBSOCKET', regex: /\bWebSocket\b/, label: 'G1 UI에서 WebSocket 사용 금지' },
  { id: 'NO_BEACON', regex: /\bsendBeacon\b/, label: 'G1 UI에서 navigator.sendBeacon 사용 금지' },
  { id: 'NO_RTC', regex: /\bRTCPeerConnection\b/, label: 'G1 UI에서 RTCPeerConnection 사용 금지' },
  { id: 'NO_NODE_NET', regex: /['"]node:(?:net|dgram|http|https|child_process)['"]/, label: 'G1 UI에서 Node 네트워크/프로세스 모듈 사용 금지' },
  { id: 'NO_TAURI_IPC', regex: /\b__TAURI__\b|@tauri-apps\//, label: 'G1에서 임의 Tauri IPC/플러그인 호출 발명 금지' },
  { id: 'NO_DYNAMIC_EVAL', regex: /\beval\s*\(|new\s+Function\s*\(/, label: '동적 코드 실행(eval/new Function) 금지' },
];

const FORBIDDEN_CONTENT_PATTERNS = [
  { id: 'NO_BANNED_PROJECT', regex: /\b(?:LibMate|SeatMate)\b/, label: '타 프로젝트(LibMate/SeatMate) 참조 금지' },
  { id: 'NO_192_168_EXAMPLE', regex: /\b192\.168\.\d{1,3}\.\d{1,3}\b/, label: '예시 192.168.* 대역 주소 사용 금지 (127.0.0.1/::1만 허용)' },
];

/**
 * 단일 소스 텍스트에 대해 정적 가드 규칙을 검사합니다.
 * @param {string} sourceText 파일 전체 문자열
 * @param {string} filePath 상대 또는 가상 파일 경로
 * @returns {Array<{ ruleId: string, message: string, line: number }>}
 */
export function scanSourceText(sourceText, filePath = 'src/unknown.ts') {
  const normalizedPath = String(filePath).replace(/\\/g, '/');
  const isSrcFile = normalizedPath.startsWith('src/') || normalizedPath.includes('/src/');
  const violations = [];

  if (sourceText.startsWith('\uFEFF')) {
    violations.push({
      ruleId: 'NO_UTF8_BOM',
      message: `${normalizedPath}: UTF-8 BOM이 포함되어 있습니다.`,
      line: 1,
    });
  }

  if (sourceText.length > 0 && !sourceText.endsWith('\n')) {
    const totalLines = sourceText.split('\n').length;
    violations.push({
      ruleId: 'REQUIRE_FINAL_NEWLINE',
      message: `${normalizedPath}: 파일 끝에 개행 문자(\\n)가 없습니다.`,
      line: totalLines,
    });
  }

  const lines = sourceText.split('\n');
  for (let idx = 0; idx < lines.length; idx += 1) {
    const rawLine = lines[idx].replace(/\r$/, '');
    const lineNumber = idx + 1;

    if (/[ \t]+$/.test(rawLine)) {
      violations.push({
        ruleId: 'NO_TRAILING_WHITESPACE',
        message: `${normalizedPath}:${lineNumber}: 줄 끝 공백(trailing whitespace)이 있습니다.`,
        line: lineNumber,
      });
    }

    for (const rule of SUPPRESSION_PATTERNS) {
      if (rawLine.includes(rule.token)) {
        violations.push({
          ruleId: rule.id,
          message: `${normalizedPath}:${lineNumber}: ${rule.label}`,
          line: lineNumber,
        });
      }
    }

    for (const rule of FORBIDDEN_CONTENT_PATTERNS) {
      if (rule.regex.test(rawLine)) {
        violations.push({
          ruleId: rule.id,
          message: `${normalizedPath}:${lineNumber}: ${rule.label}`,
          line: lineNumber,
        });
      }
    }

    if (isSrcFile) {
      for (const rule of FORBIDDEN_RUNTIME_PATTERNS) {
        if (rule.regex.test(rawLine)) {
          violations.push({
            ruleId: rule.id,
            message: `${normalizedPath}:${lineNumber}: ${rule.label}`,
            line: lineNumber,
          });
        }
      }
    }
  }

  if (isSrcFile && /["']features["']\s*:\s*\[/.test(sourceText)) {
    violations.push({
      ruleId: 'NO_CONTRACT_FEATURE_COPY',
      message: `${normalizedPath}: 중앙 계약(g1-interface-contract.json)의 기능 정의 배열을 복제하지 마십시오.`,
      line: 1,
    });
  }

  return violations;
}

/**
 * 지정된 디렉터리 하위의 소스 파일들을 재귀적으로 수집합니다.
 * @param {string} dirPath
 * @returns {string[]}
 */
function collectFiles(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return [];
  }
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const results = [];
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (/\.(ts|tsx|css|html|json|mjs)$/.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * 프로젝트 루트에서 guardlint를 실행합니다.
 * @param {string} rootDir
 * @returns {{ checkedFiles: number, violations: Array<{ ruleId: string, message: string, line: number }> }}
 */
export function runGuardLint(rootDir) {
  const targets = [
    ...collectFiles(path.join(rootDir, 'src')),
    ...collectFiles(path.join(rootDir, 'tests')),
    path.join(rootDir, 'index.html'),
    path.join(rootDir, 'package.json'),
    path.join(rootDir, 'tsconfig.json'),
    path.join(rootDir, 'vite.config.ts'),
    path.join(rootDir, 'vitest.config.ts'),
  ].filter((filePath) => fs.existsSync(filePath));

  const allViolations = [];
  for (const fullPath of targets) {
    const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');
    const content = fs.readFileSync(fullPath, 'utf8');
    const fileViolations = scanSourceText(content, relPath);
    allViolations.push(...fileViolations);
  }

  return {
    checkedFiles: targets.length,
    violations: allViolations,
  };
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(currentFile)) {
  const uiRoot = path.resolve(path.dirname(currentFile), '..');
  const { checkedFiles, violations } = runGuardLint(uiRoot);
  if (violations.length > 0) {
    console.error(`[guardlint] 실패 (ESLint 아님 — NPI G1 정적 가드 규칙 위반 ${violations.length}건):`);
    for (const v of violations) {
      console.error(` - [${v.ruleId}] ${v.message}`);
    }
    process.exit(1);
  }
  console.log(`[guardlint] 통과 (ESLint 아님 — NPI G1 정적 가드 규칙 검사 완료, 파일 ${checkedFiles}개 이상 없음)`);
}
