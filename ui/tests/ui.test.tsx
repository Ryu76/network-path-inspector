import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';

(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;

function getByTestId<T extends HTMLElement = HTMLElement>(
  container: HTMLElement,
  testId: string,
): T {
  const el = container.querySelector<T>(`[data-testid="${testId}"]`);
  if (!el) {
    throw new Error(`테스트 요소를 찾을 수 없습니다: [data-testid="${testId}"]`);
  }
  return el;
}

function setFormValue(
  element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement,
  value: string,
): void {
  const prototype =
    element instanceof HTMLSelectElement
      ? HTMLSelectElement.prototype
      : element instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
  descriptor?.set?.call(element, value);
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
}

describe('NPI G1 대시보드 React DOM 마운트 및 사용자 상호작용 검증', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    document.body.innerHTML = '';
    container = document.createElement('div');
    container.id = 'root';
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => {
      root.render(<App />);
    });
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
    vi.restoreAllMocks();
  });

  it('15. 마운트 시 G1 정직성 배너, 미검증 드라이버/백엔드(false) 상태, 비활성 진단 시작 버튼을 표시하며 자동 네트워크 요청을 수행하지 않는다', () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const banner = getByTestId(container, 'g1-engine-banner');
    expect(banner.textContent).toContain('G1 기능 선택 검증 · 실제 진단 엔진 미연결');

    const capStatus = getByTestId(container, 'capability-status');
    expect(capStatus.textContent).toContain('미검증 (false)');
    expect(capStatus.textContent).toContain('미확인 (false)');
    expect(capStatus.textContent).toContain('미확보 (false)');

    const startBtn = getByTestId<HTMLButtonElement>(container, 'start-diagnostic-btn');
    const pdfBtn = getByTestId<HTMLButtonElement>(container, 'disabled-pdf-btn');
    expect(startBtn.disabled).toBe(true);
    expect(pdfBtn.disabled).toBe(true);
    expect(pdfBtn.textContent).toContain('PDF 보고서 (G6 미연결 · 비활성)');
    expect(pdfBtn.textContent).not.toContain('G7');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('16. 초기 마운트 시 정확히 기본 5개 기능이 선택되며 6개 그룹 체크박스의 부분 선택(indeterminate) 상태가 DOM에 반영된다', () => {
    const countText = getByTestId(container, 'selected-feature-count');
    expect(countText.textContent).toContain('5 / 23개');

    const allFeatureCheckboxes = container.querySelectorAll<HTMLInputElement>(
      'input[data-testid^="feature-checkbox-"]',
    );
    expect(allFeatureCheckboxes).toHaveLength(23);
    const checkedBoxes = Array.from(allFeatureCheckboxes).filter((cb) => cb.checked);
    expect(checkedBoxes).toHaveLength(5);

    const gNetCb = getByTestId<HTMLInputElement>(container, 'group-checkbox-G-NET');
    const gPathCb = getByTestId<HTMLInputElement>(container, 'group-checkbox-G-PATH');
    const gPktCb = getByTestId<HTMLInputElement>(container, 'group-checkbox-G-PKT');
    const gEvidCb = getByTestId<HTMLInputElement>(container, 'group-checkbox-G-EVID');

    expect(gNetCb.indeterminate).toBe(true);
    expect(gNetCb.getAttribute('aria-checked')).toBe('mixed');
    expect(gPathCb.indeterminate).toBe(true);
    expect(gEvidCb.indeterminate).toBe(true);
    expect(gPktCb.checked).toBe(false);
    expect(gPktCb.indeterminate).toBe(false);
  });

  it('17. 그룹 체크박스 클릭 시 해당 그룹의 안전 기능들이 일괄 선택 및 해제되고 선택 개수가 즉시 갱신된다', () => {
    const gNetCb = getByTestId<HTMLInputElement>(container, 'group-checkbox-G-NET');
    expect(getByTestId(container, 'group-count-G-NET').textContent).toContain('2 / 3');

    act(() => {
      gNetCb.click();
    });
    expect(getByTestId(container, 'group-count-G-NET').textContent).toContain('3 / 3');
    expect(gNetCb.checked).toBe(true);
    expect(gNetCb.indeterminate).toBe(false);
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('6 / 23개');

    act(() => {
      gNetCb.click();
    });
    expect(getByTestId(container, 'group-count-G-NET').textContent).toContain('0 / 3');
    expect(gNetCb.checked).toBe(false);
    expect(gNetCb.indeterminate).toBe(false);
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('3 / 23개');
  });

  it('18. 기능 검색창 입력 시 일치하는 그룹·기능만 표시되고 검색 지우기 클릭 시 전체 6개 그룹·23개 기능이 복구된다', () => {
    const searchInput = getByTestId<HTMLInputElement>(container, 'feature-search-input');

    act(() => {
      setFormValue(searchInput, '시계 오차');
    });

    const visibleRows = container.querySelectorAll('[data-testid^="feature-row-"]');
    expect(visibleRows).toHaveLength(1);
    expect(container.querySelector('[data-testid="feature-row-clock_skew"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="group-card-G-NET"]')).toBeNull();

    const clearSearchBtn = getByTestId<HTMLButtonElement>(container, 'feature-search-clear-btn');
    act(() => {
      clearSearchBtn.click();
    });

    expect(container.querySelectorAll('[data-testid^="feature-row-"]')).toHaveLength(23);
    expect(container.querySelectorAll('[data-testid^="group-card-"]')).toHaveLength(6);
  });

  it('19. 전체 선택(안전)·전체 해제·기본 5개 복원 버튼이 DOM 상태를 정확히 전환하며 고위험 기능은 자동 선택하지 않는다', () => {
    const selectAllBtn = getByTestId<HTMLButtonElement>(container, 'select-all-btn');
    const clearAllBtn = getByTestId<HTMLButtonElement>(container, 'clear-all-btn');
    const resetDefaultBtn = getByTestId<HTMLButtonElement>(container, 'reset-default-btn');

    act(() => {
      selectAllBtn.click();
    });
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('21 / 23개');
    expect(
      getByTestId<HTMLInputElement>(container, 'feature-checkbox-packet_capture').checked,
    ).toBe(false);
    expect(
      getByTestId<HTMLInputElement>(container, 'feature-checkbox-tcp_traceroute').checked,
    ).toBe(false);

    act(() => {
      clearAllBtn.click();
    });
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('0 / 23개');

    act(() => {
      resetDefaultBtn.click();
    });
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('5 / 23개');
  });

  it('20. 비활성 기능(tcp_traceroute, 미동의 packet_capture)은 사유와 대안을 표시하며 캡처 동의 체크박스로만 packet_capture가 활성화된다', () => {
    const tcpTraceCb = getByTestId<HTMLInputElement>(container, 'feature-checkbox-tcp_traceroute');
    const pktCaptureCb = getByTestId<HTMLInputElement>(container, 'feature-checkbox-packet_capture');
    const consentCb = getByTestId<HTMLInputElement>(container, 'capture-consent-checkbox');

    expect(tcpTraceCb.disabled).toBe(true);
    expect(pktCaptureCb.disabled).toBe(true);
    expect(getByTestId(container, 'feature-disabled-reason-tcp_traceroute').textContent).toContain(
      'TCP TTL 프로브 백엔드',
    );
    expect(getByTestId(container, 'feature-disabled-reason-packet_capture').textContent).toContain(
      '별도 명시적 동의',
    );

    act(() => {
      consentCb.click();
    });
    expect(consentCb.checked).toBe(true);
    expect(pktCaptureCb.disabled).toBe(false);

    act(() => {
      pktCaptureCb.click();
    });
    expect(pktCaptureCb.checked).toBe(true);
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('6 / 23개');

    act(() => {
      consentCb.click();
    });
    expect(consentCb.checked).toBe(false);
    expect(pktCaptureCb.checked).toBe(false);
    expect(pktCaptureCb.disabled).toBe(true);
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('5 / 23개');
  });

  it('21. 프리셋 버튼 클릭 시 해당 프리셋 기능으로 전환되며 패킷 캡처 동의는 절대 자동 승인되지 않는다', () => {
    const consentCb = getByTestId<HTMLInputElement>(container, 'capture-consent-checkbox');
    act(() => {
      consentCb.click();
    });
    expect(consentCb.checked).toBe(true);

    const preciseBtn = getByTestId<HTMLButtonElement>(container, 'preset-btn-precise-default');
    act(() => {
      preciseBtn.click();
    });

    expect(consentCb.checked).toBe(false);
    expect(
      getByTestId<HTMLInputElement>(container, 'feature-checkbox-syn_rst_analysis').checked,
    ).toBe(true);
    expect(
      getByTestId<HTMLInputElement>(container, 'feature-checkbox-packet_capture').checked,
    ).toBe(false);

    const pairedBtn = getByTestId<HTMLButtonElement>(container, 'preset-btn-paired-default');
    act(() => {
      pairedBtn.click();
    });
    expect(getByTestId<HTMLSelectElement>(container, 'mode-select').value).toBe('paired_offline');
    expect(consentCb.checked).toBe(false);
  });

  it('22. 대상 호스트 및 TCP 포트 입력란은 잘못된 주소·포트 범위에 대해 즉시 한국어 검증 오류를 표시한다', () => {
    const hostInput = getByTestId<HTMLInputElement>(container, 'target-host-input');
    const portInput = getByTestId<HTMLInputElement>(container, 'target-port-input');

    act(() => {
      setFormValue(hostInput, 'http://127.0.0.1');
    });
    expect(getByTestId(container, 'target-validation-msg').textContent).toContain('URI 스킴');

    act(() => {
      setFormValue(hostInput, '::1');
      setFormValue(portInput, '70000');
    });
    expect(getByTestId(container, 'target-validation-msg').textContent).toContain('65535');

    act(() => {
      setFormValue(portInput, '1526');
    });
    expect(container.querySelector('[data-testid="target-validation-msg"]')).toBeNull();
  });

  it('23. 프로파일 JSON 내보내기 및 복원 시 개인정보 안내를 표시하고 고위험 기능·캡처 동의를 자동 제거하며 경고를 출력한다', () => {
    const privacyWarning = getByTestId(container, 'profile-privacy-warning');
    expect(privacyWarning.textContent).toContain('PDF 미생성');

    const exportBtn = getByTestId<HTMLButtonElement>(container, 'export-profile-btn');
    const textarea = getByTestId<HTMLTextAreaElement>(container, 'profile-json-textarea');
    const restoreBtn = getByTestId<HTMLButtonElement>(container, 'restore-profile-btn');

    act(() => {
      exportBtn.click();
    });
    expect(textarea.value).toContain('"profile_id": "quick-default"');

    const riskyPayload = JSON.stringify({
      schema_version: '1.1',
      profile_id: 'imported-risk',
      label: '외부 고위험 프로파일',
      mode: 'standalone',
      capture_approved: true,
      selected_features: ['tcp_connect', 'packet_capture', 'tcp_traceroute', 'old_removed_probe'],
      target: { host: '127.0.0.1', port: 443, protocol: 'TCP' },
    });

    act(() => {
      setFormValue(textarea, riskyPayload);
    });
    act(() => {
      restoreBtn.click();
    });

    expect(getByTestId<HTMLInputElement>(container, 'capture-consent-checkbox').checked).toBe(
      false,
    );
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('1 / 23개');
    const warningsBox = getByTestId(container, 'restore-profile-warnings');
    expect(warningsBox.textContent).toContain('packet_capture');
    expect(warningsBox.textContent).toContain('old_removed_probe');

    act(() => {
      setFormValue(textarea, 'not-a-json');
    });
    act(() => {
      restoreBtn.click();
    });
    expect(getByTestId(container, 'restore-profile-error').textContent).toContain(
      '유효하지 않은 프로파일 JSON',
    );
  });

  it('24. 세션 스냅샷 고정 중에는 현재 세션 선택 개수가 불변(5개)으로 유지되고 변경 사항은 다음 세션 대기열에만 저장된다', () => {
    const snapshotBtn = getByTestId<HTMLButtonElement>(container, 'snapshot-lock-btn');
    const clearAllBtn = getByTestId<HTMLButtonElement>(container, 'clear-all-btn');

    act(() => {
      snapshotBtn.click();
    });
    expect(getByTestId(container, 'locked-snapshot-count').textContent).toBe('5');

    act(() => {
      clearAllBtn.click();
    });
    expect(getByTestId(container, 'locked-snapshot-count').textContent).toBe('5');
    expect(getByTestId(container, 'queued-snapshot-count').textContent).toBe('0');

    act(() => {
      snapshotBtn.click();
    });
    expect(getByTestId(container, 'selected-feature-count').textContent).toContain('0 / 23개');
  });

  it('25. 초기 결과 패널은 EMPTY(PASS 아님) 상태이며 그룹별 탭에서도 6개 그룹 모두 EMPTY(미실행)로 표시된다', () => {
    const emptyState = getByTestId(container, 'empty-results-state');
    expect(emptyState.textContent).toContain('EMPTY');
    expect(container.querySelector('[data-testid="synthetic-fixture-banner"]')).toBeNull();

    expect(getByTestId(container, 'status-count-PASS').textContent).toBe('0');
    expect(getByTestId(container, 'status-count-FAIL').textContent).toBe('0');

    const groupsTabBtn = getByTestId<HTMLButtonElement>(container, 'result-tab-groups');
    act(() => {
      groupsTabBtn.click();
    });

    for (const gid of ['G-NET', 'G-PATH', 'G-PKT', 'G-PAIR', 'G-OPS', 'G-EVID']) {
      const badge = getByTestId(container, `group-summary-status-${gid}`);
      expect(badge.textContent).toContain('EMPTY');
      expect(badge.textContent).not.toBe('PASS');
    }
  });

  it('26. 합성 예시 보기 스위치 활성화 시 합성 배너와 7종 분리 상태를 표시하고 그룹·기능·상태·근거수준·검색 필터가 동작한다', () => {
    const syntheticToggle = getByTestId<HTMLInputElement>(container, 'synthetic-fixture-toggle');

    act(() => {
      syntheticToggle.click();
    });

    const synBanner = getByTestId(container, 'synthetic-fixture-banner');
    expect(synBanner.textContent).toContain('SYNTHETIC FIXTURE');

    expect(Number(getByTestId(container, 'status-count-PASS').textContent)).toBeGreaterThan(0);
    expect(Number(getByTestId(container, 'status-count-FAIL').textContent)).toBeGreaterThan(0);
    expect(Number(getByTestId(container, 'status-count-SKIPPED_BY_USER').textContent)).toBeGreaterThan(0);
    expect(Number(getByTestId(container, 'status-count-UNAVAILABLE').textContent)).toBeGreaterThan(0);
    expect(Number(getByTestId(container, 'status-count-ERROR').textContent)).toBeGreaterThan(0);
    expect(Number(getByTestId(container, 'status-count-CANCELLED').textContent)).toBeGreaterThan(0);

    const featuresTabBtn = getByTestId<HTMLButtonElement>(container, 'result-tab-features');
    act(() => {
      featuresTabBtn.click();
    });
    expect(getByTestId(container, 'filtered-result-count').textContent).toContain('13 / 전체 13건');

    const statusSelect = getByTestId<HTMLSelectElement>(container, 'filter-status-select');
    act(() => {
      setFormValue(statusSelect, 'ERROR');
    });
    expect(getByTestId(container, 'filtered-result-count').textContent).toContain('1 / 전체 13건');
    expect(container.querySelector('[data-testid="result-item-firewall_log"]')).not.toBeNull();

    const resetBtn = getByTestId<HTMLButtonElement>(container, 'filter-reset-btn');
    act(() => {
      resetBtn.click();
    });
    expect(getByTestId(container, 'filtered-result-count').textContent).toContain('13 / 전체 13건');

    const groupSelect = getByTestId<HTMLSelectElement>(container, 'filter-group-select');
    const classSelect = getByTestId<HTMLSelectElement>(container, 'filter-classification-select');
    act(() => {
      setFormValue(groupSelect, 'G-PATH');
      setFormValue(classSelect, 'INFERRED');
    });
    expect(getByTestId(container, 'filtered-result-count').textContent).toContain('1 / 전체 13건');
    expect(container.querySelector('[data-testid="result-item-icmp_traceroute"]')).not.toBeNull();
  });
});
