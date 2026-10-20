import { describe, expect, it } from 'vitest';
import {
  aggregateGroups,
  applyProfileChangeDuringSession,
  clearAllFeatures,
  cloneProfile,
  createDefaultProfile,
  createExecutionSelectionState,
  DEFAULT_G1_CAPABILITIES,
  detectActivePresetId,
  estimateProfileDurationMs,
  type FeatureResult,
  filterResults,
  flattenSessionResults,
  G1_CONTRACT,
  getFeatureDefinition,
  getFeatureDisabledInfo,
  getGroupSelectionState,
  isFeatureDisabled,
  isKnownFeatureId,
  lockSessionProfileSnapshot,
  migrateLegacySession,
  releaseSessionProfileSnapshot,
  restoreProfile,
  selectAllFeatures,
  selectPreset,
  setCaptureConsent,
  STATUS_METADATA,
  toggleFeature,
  toggleGroupFeatures,
  validateAndRestoreProfile,
  validateLimits,
  validateTarget,
} from '../src/domain';
import { SYNTHETIC_EXAMPLE_SESSION } from '../src/fixtures/syntheticFixture';

describe('NPI G1 도메인 계약 및 상태 순수 함수 검증', () => {
  it('1. 중앙 계약(G1_CONTRACT)은 정확히 6개 그룹·23개 기능을 가지며 첫 실행 기본 프로파일은 정확히 5개 기능을 선택한다', () => {
    expect(G1_CONTRACT.groups).toHaveLength(6);
    expect(G1_CONTRACT.features).toHaveLength(23);

    const profile = createDefaultProfile();
    expect(profile.schema_version).toBe('1.1');
    expect(profile.profile_id).toBe('quick-default');
    expect(profile.mode).toBe('standalone');
    expect(profile.capture_approved).toBe(false);
    expect(profile.target).toEqual({
      host: '127.0.0.1',
      port: 1526,
      protocol: 'TCP',
    });
    expect(profile.selected_features).toEqual([
      'tcp_connect',
      'icmp_ping',
      'route_table',
      'nic_inventory',
      'result_json',
    ]);
    expect(profile.selected_features).toHaveLength(5);
    expect(detectActivePresetId(profile)).toBe('quick-default');
    expect(estimateProfileDurationMs(profile)).toBeGreaterThan(0);
  });

  it('2. 그룹 선택 상태(getGroupSelectionState)와 그룹 토글(toggleGroupFeatures)은 부분 선택(indeterminate)과 전체 선택/해제를 정확히 계산한다', () => {
    const initial = createDefaultProfile();

    const gNetPartial = getGroupSelectionState(initial, 'G-NET');
    expect(gNetPartial.total_count).toBe(3);
    expect(gNetPartial.selected_count).toBe(2);
    expect(gNetPartial.checked).toBe(false);
    expect(gNetPartial.indeterminate).toBe(true);

    const gNetAll = toggleGroupFeatures(initial, 'G-NET', true);
    const gNetChecked = getGroupSelectionState(gNetAll, 'G-NET');
    expect(gNetChecked.selected_count).toBe(3);
    expect(gNetChecked.checked).toBe(true);
    expect(gNetChecked.indeterminate).toBe(false);

    const gNetCleared = toggleGroupFeatures(gNetAll, 'G-NET', false);
    const gNetEmpty = getGroupSelectionState(gNetCleared, 'G-NET');
    expect(gNetEmpty.selected_count).toBe(0);
    expect(gNetEmpty.checked).toBe(false);
    expect(gNetEmpty.indeterminate).toBe(false);

    const gPktToggled = toggleGroupFeatures(initial, 'G-PKT', true);
    expect(gPktToggled.selected_features).not.toContain('packet_capture');
    expect(gPktToggled.selected_features).toContain('syn_rst_analysis');
    expect(gPktToggled.selected_features).toContain('firewall_log');
    expect(gPktToggled.selected_features).toContain('listening_check');
  });

  it('3. 미검증 tcp_traceroute 및 동의 없는 packet_capture는 비활성 처리되며 명시적 사유와 대안을 반환한다', () => {
    expect(DEFAULT_G1_CAPABILITIES).toEqual({
      validated_tcp_ttl_backend: false,
      npcap_installed: false,
      capture_privilege_available: false,
    });

    const profile = createDefaultProfile();
    const tcpTraceInfo = getFeatureDisabledInfo('tcp_traceroute', profile);
    expect(tcpTraceInfo.disabled).toBe(true);
    expect(tcpTraceInfo.reason).toContain('TCP TTL');
    expect(tcpTraceInfo.alternative).toContain('icmp_traceroute');

    const attemptedTcpTrace = toggleFeature(profile, 'tcp_traceroute', true);
    expect(attemptedTcpTrace.selected_features).not.toContain('tcp_traceroute');

    const captureInfo = getFeatureDisabledInfo('packet_capture', profile);
    expect(captureInfo.disabled).toBe(true);
    expect(captureInfo.requiresConsent).toBe(true);
    expect(captureInfo.reason).toContain('별도 명시적 동의');
    expect(isFeatureDisabled('packet_capture', profile)).toBe(true);
  });

  it('4. 프리셋 선택(selectPreset)은 절대 패킷 캡처 동의(capture_approved)를 자동 부여하지 않으며 고위험/비활성 기능을 제외한다', () => {
    const consentedProfile = setCaptureConsent(createDefaultProfile(), true);
    expect(consentedProfile.capture_approved).toBe(true);

    const pathProfile = selectPreset(consentedProfile, 'path-default');
    expect(pathProfile.capture_approved).toBe(false);
    expect(pathProfile.selected_features).toContain('icmp_traceroute');
    expect(pathProfile.selected_features).not.toContain('tcp_traceroute');
    expect(pathProfile.selected_features).not.toContain('packet_capture');

    const preciseProfile = selectPreset(consentedProfile, 'precise-default');
    expect(preciseProfile.capture_approved).toBe(false);
    expect(preciseProfile.selected_features).toContain('syn_rst_analysis');
    expect(preciseProfile.selected_features).not.toContain('packet_capture');

    const pairedProfile = selectPreset(consentedProfile, 'paired-default');
    expect(pairedProfile.mode).toBe('paired_offline');
    expect(pairedProfile.capture_approved).toBe(false);
    expect(pairedProfile.selected_features).toContain('agent_session');
    expect(pairedProfile.selected_features).toContain('packet_compare');
  });

  it('5. 패킷 캡처 명시적 동의(setCaptureConsent) 승인 후에만 packet_capture 선택이 가능하며 동의 해제 시 즉시 선택 해제된다', () => {
    const base = createDefaultProfile();
    const blocked = toggleFeature(base, 'packet_capture', true);
    expect(blocked.selected_features).not.toContain('packet_capture');

    const approved = setCaptureConsent(base, true);
    expect(approved.capture_approved).toBe(true);
    expect(isFeatureDisabled('packet_capture', approved)).toBe(false);

    const withCapture = toggleFeature(approved, 'packet_capture', true);
    expect(withCapture.selected_features).toContain('packet_capture');

    const revoked = setCaptureConsent(withCapture, false);
    expect(revoked.capture_approved).toBe(false);
    expect(revoked.selected_features).not.toContain('packet_capture');
  });

  it('6. 전체 선택(selectAllFeatures)은 안전 기능만 활성화하고 전체 해제(clearAllFeatures)는 선택 및 동의를 모두 비운다', () => {
    const base = createDefaultProfile();
    const allSafe = selectAllFeatures(base);

    expect(allSafe.selected_features.length).toBe(21);
    expect(allSafe.selected_features).not.toContain('packet_capture');
    expect(allSafe.selected_features).not.toContain('tcp_traceroute');
    expect(allSafe.capture_approved).toBe(false);

    const cleared = clearAllFeatures(setCaptureConsent(allSafe, true));
    expect(cleared.selected_features).toEqual([]);
    expect(cleared.capture_approved).toBe(false);
  });

  it('7. 프로파일 복원(restoreProfile)은 고위험 기능과 캡처 동의를 강제 해제하고 미지원 레거시 기능 경고를 반환한다', () => {
    const riskySavedJson = JSON.stringify({
      schema_version: '1.0',
      profile_id: 'saved-risky',
      label: '외부 저장 프로파일',
      mode: 'standalone',
      capture_approved: true,
      selected_features: [
        'tcp_connect',
        'packet_capture',
        'tcp_traceroute',
        'legacy_unknown_probe',
      ],
      target: {
        host: '127.0.0.1',
        port: 8443,
        protocol: 'TCP',
      },
    });

    const restored = restoreProfile(riskySavedJson);
    expect(restored.schema_version).toBe('1.1');
    expect(restored.capture_approved).toBe(false);
    expect(restored.selected_features).toEqual(['tcp_connect']);
    expect(restored.stripped_high_cost_features).toEqual([
      'packet_capture',
      'tcp_traceroute',
    ]);
    expect(restored.ignored_features).toEqual(['legacy_unknown_probe']);
    expect(restored.legacy_migrated).toBe(true);
    expect(restored.restore_warnings.length).toBeGreaterThanOrEqual(3);

    const cloned = cloneProfile(restored);
    expect(cloned.capture_approved).toBe(false);
    expect(cloned.profile_id).toBe('saved-risky-copy');

    const badOutcome = validateAndRestoreProfile('{ invalid json');
    expect(badOutcome.ok).toBe(false);
    expect(badOutcome.error).toContain('유효하지 않은 프로파일 JSON');
  });

  it('8. 대상 호스트/포트(validateTarget) 및 제한 설정(validateLimits) 검증은 비정상 입력을 거부하고 루프백 단일 대상을 허용한다', () => {
    expect(validateTarget({ host: '127.0.0.1', port: 1526, protocol: 'TCP' }).valid).toBe(true);
    expect(validateTarget({ host: '::1', port: 443, protocol: 'TCP' }).valid).toBe(true);

    expect(validateTarget({ host: 'http://127.0.0.1', port: 80, protocol: 'TCP' }).valid).toBe(false);
    expect(validateTarget({ host: 'user@127.0.0.1', port: 80, protocol: 'TCP' }).valid).toBe(false);
    expect(validateTarget({ host: '127.0.0.1/24', port: 80, protocol: 'TCP' }).valid).toBe(false);
    expect(validateTarget({ host: '127.0.0.1:8080', port: 80, protocol: 'TCP' }).valid).toBe(false);
    expect(validateTarget({ host: '127.0.0.1', port: 70000, protocol: 'TCP' }).valid).toBe(false);

    expect(validateLimits({ tcp_timeout_ms: 5000, max_hops: 30 }).valid).toBe(true);
    expect(validateLimits({ tcp_timeout_ms: 50, max_hops: 30 }).valid).toBe(false);
    expect(validateLimits({ tcp_timeout_ms: 5000, max_hops: 99 }).valid).toBe(false);
  });

  it('9. 세션 실행 중 프로파일 스냅샷(lockSessionProfileSnapshot)은 현재 세션 구성을 동결하고 편집 사항을 대기열(queued_next_profile)에만 적재한다', () => {
    const initialState = createExecutionSelectionState(createDefaultProfile());
    expect(initialState.is_running).toBe(false);

    const lockedState = lockSessionProfileSnapshot(initialState);
    expect(lockedState.is_running).toBe(true);
    expect(lockedState.current_session_profile?.selected_features).toHaveLength(5);
    expect(Object.isFrozen(lockedState.current_session_profile)).toBe(true);

    const clearedProfile = clearAllFeatures(lockedState.active_profile);
    const busyEditedState = applyProfileChangeDuringSession(lockedState, clearedProfile);

    expect(busyEditedState.current_session_profile?.selected_features).toHaveLength(5);
    expect(busyEditedState.queued_next_profile?.selected_features).toHaveLength(0);

    const releasedState = releaseSessionProfileSnapshot(busyEditedState);
    expect(releasedState.is_running).toBe(false);
    expect(releasedState.current_session_profile).toBeNull();
    expect(releasedState.queued_next_profile).toBeNull();
    expect(releasedState.active_profile.selected_features).toHaveLength(0);
  });

  it('10. 빈 결과 집계(aggregateGroups([]))는 6개 그룹 모두 EMPTY 상태를 반환하며 절대 PASS로 위장하지 않는다', () => {
    const emptyGroups = aggregateGroups([]);
    expect(emptyGroups).toHaveLength(6);

    for (const grp of emptyGroups) {
      expect(grp.summary_status).toBe('EMPTY');
      expect(grp.summary_status).not.toBe('PASS');
      expect(grp.has_executed).toBe(false);
      expect(grp.result_count).toBe(0);
    }
  });

  it('11. 결과 상태 분리: SKIPPED_BY_USER, UNAVAILABLE, ERROR, CANCELLED는 PASS/FAIL로 합산되지 않고 독립 상태로 집계된다', () => {
    const sampleResults: FeatureResult[] = [
      {
        feature_id: 'dns_lookup',
        group_id: 'G-NET',
        status: 'SKIPPED_BY_USER',
        classification: null,
        evidence_ids: [],
        started_at_utc: null,
        ended_at_utc: null,
        duration_ms: null,
        error_code: null,
        limitations: [],
        next_checks: [],
      },
      {
        feature_id: 'tcp_traceroute',
        group_id: 'G-PATH',
        status: 'UNAVAILABLE',
        classification: 'UNKNOWN',
        evidence_ids: [],
        started_at_utc: null,
        ended_at_utc: null,
        duration_ms: null,
        error_code: null,
        limitations: [],
        next_checks: [],
      },
      {
        feature_id: 'firewall_log',
        group_id: 'G-PKT',
        status: 'ERROR',
        classification: 'UNKNOWN',
        evidence_ids: [],
        started_at_utc: '2026-10-20T04:00:08Z',
        ended_at_utc: '2026-10-20T04:00:09Z',
        duration_ms: 100,
        error_code: 5,
        limitations: [],
        next_checks: [],
      },
      {
        feature_id: 'tcp_monitor',
        group_id: 'G-OPS',
        status: 'CANCELLED',
        classification: 'OBSERVED',
        evidence_ids: [],
        started_at_utc: '2026-10-20T04:00:10Z',
        ended_at_utc: '2026-10-20T04:00:12Z',
        duration_ms: 500,
        error_code: null,
        limitations: [],
        next_checks: [],
      },
    ];

    const aggregated = aggregateGroups(sampleResults);
    const byGroup = Object.fromEntries(aggregated.map((g) => [g.group_id, g]));

    expect(byGroup['G-NET'].summary_status).toBe('SKIPPED_BY_USER');
    expect(byGroup['G-NET'].counts.PASS).toBe(0);
    expect(byGroup['G-NET'].counts.FAIL).toBe(0);

    expect(byGroup['G-PATH'].summary_status).toBe('UNAVAILABLE');
    expect(byGroup['G-PKT'].summary_status).toBe('ERROR');
    expect(byGroup['G-OPS'].summary_status).toBe('CANCELLED');
    expect(byGroup['G-PAIR'].summary_status).toBe('EMPTY');

    expect(STATUS_METADATA.SKIPPED_BY_USER.koreanLabel).toBe('사용자 미선택');
    expect(STATUS_METADATA.UNAVAILABLE.koreanLabel).toBe('미지원/의존성 부족');
  });

  it('12. 다차원 결과 필터(filterResults)는 그룹·기능·상태·근거수준·검색어·정렬 조건을 원본 변이 없이 정확히 수행한다', () => {
    const flat = flattenSessionResults(SYNTHETIC_EXAMPLE_SESSION);
    expect(flat.length).toBeGreaterThanOrEqual(10);

    const byGroup = filterResults(flat, { group_id: 'G-PATH' });
    expect(byGroup.every((r) => r.group_id === 'G-PATH')).toBe(true);
    expect(byGroup).toHaveLength(4);

    const byFeature = filterResults(flat, { feature_id: 'firewall_log' });
    expect(byFeature).toHaveLength(1);
    expect(byFeature[0].status).toBe('ERROR');

    const byStatus = filterResults(flat, { status: 'UNAVAILABLE' });
    expect(byStatus.map((r) => r.feature_id)).toEqual(['tcp_traceroute', 'syn_rst_analysis']);

    const byClassification = filterResults(flat, { classification: 'INFERRED' });
    expect(byClassification.map((r) => r.feature_id)).toEqual(['icmp_traceroute', 'clock_skew']);

    const bySearch = filterResults(flat, { search: '시계 오차' });
    expect(bySearch).toHaveLength(1);
    expect(bySearch[0].feature_id).toBe('clock_skew');

    const sortedByStatus = filterResults(flat, { sort_by: 'status', sort_order: 'asc' });
    expect(sortedByStatus[0].status).toBe('FAIL');
  });

  it('13. 구버전(1.0) 세션 변환(migrateLegacySession)은 원본 데이터를 동결 보존하고 가짜 PASS 결과를 생성하지 않는다', () => {
    const legacyRaw = {
      schema_version: '1.0',
      session_id: 'old-session-01',
      mode: 'standalone',
    };
    const migrated = migrateLegacySession(legacyRaw);

    expect(migrated.schema_version).toBe('1.1');
    expect(migrated.session_id).toBe('old-session-01');
    expect(migrated.feature_results).toEqual([]);
    expect(migrated.findings[0].classification).toBe('UNKNOWN');
    expect(migrated.raw_legacy_input).toEqual(legacyRaw);
    expect(Object.isFrozen(migrated.raw_legacy_input)).toBe(true);
  });

  it('14. 기능 정의 조회(getFeatureDefinition) 및 ID 판별(isKnownFeatureId)이 23개 표준 기능 전체에 대해 일관되게 동작한다', () => {
    for (const feat of G1_CONTRACT.features) {
      expect(isKnownFeatureId(feat.feature_id)).toBe(true);
      expect(getFeatureDefinition(feat.feature_id)?.label).toBeTruthy();
    }
    expect(isKnownFeatureId('unknown_fake_feature')).toBe(false);
  });
});
