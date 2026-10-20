import { type ChangeEvent, useMemo, useState } from 'react';
import { FeatureSelectionPanel } from './components/FeatureSelectionPanel';
import { ResultPanel } from './components/ResultPanel';
import { PRESET_DISPLAY_LIST } from './contracts/g1Contract';
import {
  applyProfileChangeDuringSession,
  createDefaultProfile,
  createExecutionSelectionState,
  DEFAULT_G1_CAPABILITIES,
  detectActivePresetId,
  type DiagnosticMode,
  G1_CONTRACT,
  getFeatureDisabledInfo,
  lockSessionProfileSnapshot,
  type Profile,
  releaseSessionProfileSnapshot,
  restoreProfile,
  selectPreset,
  setCaptureConsent,
  validateTarget,
} from './domain';

export function App() {
  const [execState, setExecState] = useState(() =>
    createExecutionSelectionState(createDefaultProfile()),
  );
  const profile = execState.active_profile;

  const [hostInput, setHostInput] = useState<string>(profile.target.host);
  const [portInput, setPortInput] = useState<string>(String(profile.target.port));
  const [showSynthetic, setShowSynthetic] = useState<boolean>(false);
  const [profileJsonText, setProfileJsonText] = useState<string>('');
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [restoreWarnings, setRestoreWarnings] = useState<string[]>([]);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const updateProfile = (nextProfile: Profile) => {
    setExecState((prev) => applyProfileChangeDuringSession(prev, nextProfile));
  };

  const activePresetId = useMemo(
    () => detectActivePresetId(profile, DEFAULT_G1_CAPABILITIES),
    [profile],
  );

  const targetValidation = useMemo(
    () =>
      validateTarget({
        host: hostInput,
        port: Number(portInput),
        protocol: 'TCP',
      }),
    [hostInput, portInput],
  );

  const handleModeChange = (nextMode: DiagnosticMode) => {
    const updated: Profile = {
      ...profile,
      mode: nextMode,
      selected_features: profile.selected_features.filter(
        (fid) =>
          !getFeatureDisabledInfo(
            fid,
            { ...profile, mode: nextMode },
            DEFAULT_G1_CAPABILITIES,
          ).disabled,
      ),
    };
    updateProfile(updated);
  };

  const handlePresetClick = (presetId: string) => {
    const next = selectPreset(profile, presetId, DEFAULT_G1_CAPABILITIES);
    updateProfile(next);
  };

  const handleHostChange = (val: string) => {
    setHostInput(val);
    const check = validateTarget({ host: val, port: Number(portInput), protocol: 'TCP' });
    if (check.valid) {
      updateProfile({
        ...profile,
        target: { host: val.trim(), port: Number(portInput), protocol: 'TCP' },
      });
    }
  };

  const handlePortChange = (val: string) => {
    setPortInput(val);
    const numPort = Number(val);
    const check = validateTarget({ host: hostInput, port: numPort, protocol: 'TCP' });
    if (check.valid) {
      updateProfile({
        ...profile,
        target: { host: hostInput.trim(), port: numPort, protocol: 'TCP' },
      });
    }
  };

  const handleExportProfile = () => {
    const serialized = JSON.stringify(profile, null, 2);
    setProfileJsonText(serialized);
    setRestoreError(null);
    setExportNotice(
      '현재 프로파일 설정 JSON이 생성되었습니다 (PDF/PCAP 아님). 외부 공유 전 대상 호스트·포트 포함 여부를 확인하십시오.',
    );
  };

  const handleFileImport = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      setProfileJsonText(content);
    };
    reader.readAsText(file, 'utf-8');
  };

  const handleRestoreProfile = () => {
    setExportNotice(null);
    try {
      const restored = restoreProfile(profileJsonText, DEFAULT_G1_CAPABILITIES);
      setRestoreError(null);
      setRestoreWarnings(restored.restore_warnings);
      setHostInput(restored.target.host);
      setPortInput(String(restored.target.port));
      updateProfile({
        schema_version: restored.schema_version,
        profile_id: restored.profile_id,
        label: restored.label,
        mode: restored.mode,
        selected_features: restored.selected_features,
        capture_approved: false,
        target: restored.target,
        limits: restored.limits,
      });
    } catch (err) {
      setRestoreWarnings([]);
      setRestoreError(err instanceof Error ? err.message : '프로파일 복원 실패');
    }
  };

  const handleToggleSnapshotLock = () => {
    setExecState((prev) =>
      prev.is_running ? releaseSessionProfileSnapshot(prev) : lockSessionProfileSnapshot(prev),
    );
  };

  return (
    <div className="app-shell">
      <header className="top-header">
        <div className="brand-block">
          <div className="brand-title-row">
            <h1>Network Path Inspector</h1>
            <span className="version-chip">Schema v{G1_CONTRACT.schema_version}</span>
          </div>
          <div className="g1-honest-banner" data-testid="g1-engine-banner" role="status">
            <strong>G1 기능 선택 검증 · 실제 진단 엔진 미연결</strong>
            <span>
              실제 소켓/ICMP/DNS 프로브·패킷 캡처·PDF 생성·모니터링 요청을 수행하지 않으며,
              23개 기능(6개 그룹) 계약 및 상태 분리 UI만 검증합니다.
            </span>
          </div>
        </div>

        <div className="header-controls">
          <div className="capability-pills" data-testid="capability-status">
            <span className="cap-pill">
              TCP TTL 백엔드:{' '}
              <strong>미검증 ({String(DEFAULT_G1_CAPABILITIES.validated_tcp_ttl_backend)})</strong>
            </span>
            <span className="cap-pill">
              Npcap 드라이버:{' '}
              <strong>미확인 ({String(DEFAULT_G1_CAPABILITIES.npcap_installed)})</strong>
            </span>
            <span className="cap-pill">
              캡처 권한:{' '}
              <strong>미확보 ({String(DEFAULT_G1_CAPABILITIES.capture_privilege_available)})</strong>
            </span>
          </div>
          <div className="engine-action-row">
            <button
              type="button"
              className="btn btn-disabled-engine"
              data-testid="start-diagnostic-btn"
              disabled
              title="G1 단계에서는 실제 진단 엔진이 연결되지 않아 실행할 수 없습니다."
            >
              진단 시작 (엔진 미연결 · 비활성)
            </button>
            <button
              type="button"
              className="btn btn-disabled-engine"
              data-testid="disabled-pdf-btn"
              disabled
              title="G1 단계에서는 PDF/PCAP 보고서 생성기를 제공하지 않습니다."
            >
              PDF 보고서 (G7 미연결 · 비활성)
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              data-testid="snapshot-lock-btn"
              onClick={handleToggleSnapshotLock}
            >
              {execState.is_running
                ? '세션 스냅샷 고정 해제 (대기열 반영)'
                : '세션 중 스냅샷 고정 검증'}
            </button>
          </div>
        </div>
      </header>

      <section className="config-strip" aria-labelledby="config-heading">
        <div className="config-top-grid">
          <div className="config-card">
            <h2 id="config-heading" className="panel-title">
              진단 모드 · 프리셋 · 대상 호스트/포트
            </h2>
            <div className="form-row">
              <div className="form-field">
                <label htmlFor="mode-select">진단 모드</label>
                <select
                  id="mode-select"
                  data-testid="mode-select"
                  value={profile.mode}
                  onChange={(e) => handleModeChange(e.target.value as DiagnosticMode)}
                >
                  <option value="standalone">단독 진단 (standalone)</option>
                  <option value="paired_offline">양방향 오프라인 비교 (paired_offline)</option>
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="target-host-input">대상 호스트 (단일 IP/도메인)</label>
                <input
                  id="target-host-input"
                  data-testid="target-host-input"
                  type="text"
                  value={hostInput}
                  onChange={(e) => handleHostChange(e.target.value)}
                  placeholder="127.0.0.1 또는 ::1"
                />
              </div>
              <div className="form-field form-field-port">
                <label htmlFor="target-port-input">TCP 포트 (1~65535)</label>
                <input
                  id="target-port-input"
                  data-testid="target-port-input"
                  type="number"
                  min={1}
                  max={65535}
                  value={portInput}
                  onChange={(e) => handlePortChange(e.target.value)}
                />
              </div>
            </div>

            {(!targetValidation.valid || targetValidation.hostError || targetValidation.portError) && (
              <div className="validation-error" data-testid="target-validation-msg" role="alert">
                {targetValidation.hostError ?? targetValidation.portError}
              </div>
            )}

            <div className="preset-bar" role="group" aria-label="진단 프리셋 선택">
              {PRESET_DISPLAY_LIST.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  data-testid={`preset-btn-${preset.id}`}
                  aria-pressed={activePresetId === preset.id}
                  className={`preset-chip ${activePresetId === preset.id ? 'active' : ''}`}
                  onClick={() => handlePresetClick(preset.id)}
                  title={preset.description}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="consent-bar">
              <label className="consent-label">
                <input
                  type="checkbox"
                  data-testid="capture-consent-checkbox"
                  checked={profile.capture_approved}
                  onChange={(e) => updateProfile(setCaptureConsent(profile, e.target.checked))}
                />
                <span>
                  패킷 캡처 별도 명시적 동의 (프리셋·전체선택·프로파일 복원으로 자동 승인되지 않음)
                </span>
              </label>
            </div>

            <div className="snapshot-info" data-testid="snapshot-status-box">
              {execState.is_running && execState.current_session_profile ? (
                <span>
                  [세션 스냅샷 고정 중] 현재 세션 고정 기능:{' '}
                  <strong data-testid="locked-snapshot-count">
                    {execState.current_session_profile.selected_features.length}
                  </strong>
                  개 · 다음 세션 대기열(queued_next_profile):{' '}
                  <strong data-testid="queued-snapshot-count">
                    {execState.queued_next_profile?.selected_features.length ??
                      profile.selected_features.length}
                  </strong>
                  개
                </span>
              ) : (
                <span>[비실행 상태] 기능 선택 변경이 현재 프로파일에 즉시 반영됩니다.</span>
              )}
            </div>
          </div>

          <div className="config-card profile-io-card">
            <h2 className="panel-title">프로파일 JSON 내보내기 · 복원 검증</h2>
            <p className="privacy-note" data-testid="profile-privacy-warning">
              주의: 프로파일 JSON에는 대상 호스트·포트 설정이 포함될 수 있으므로 외부 공유 시 민감정보를 확인하십시오(PDF 미생성).
              프로파일 복원 시 고위험 기능(<code>packet_capture</code>, <code>tcp_traceroute</code>) 및 캡처 동의는 안전 정책에 따라 자동 해제됩니다.
            </p>
            <div className="io-actions">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                data-testid="export-profile-btn"
                onClick={handleExportProfile}
              >
                현재 프로파일 JSON 내보내기
              </button>
              <label className="file-upload-label btn btn-secondary btn-sm">
                <span>JSON 파일 불러오기</span>
                <input
                  type="file"
                  accept=".json,application/json"
                  data-testid="import-profile-file-input"
                  onChange={handleFileImport}
                />
              </label>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                data-testid="restore-profile-btn"
                onClick={handleRestoreProfile}
              >
                검증 후 프로파일 복원 적용
              </button>
            </div>
            <textarea
              className="profile-json-textarea"
              data-testid="profile-json-textarea"
              rows={3}
              placeholder="프로파일 JSON을 붙여넣거나 '현재 프로파일 JSON 내보내기'를 클릭하십시오."
              value={profileJsonText}
              onChange={(e) => setProfileJsonText(e.target.value)}
            />
            {exportNotice && (
              <div className="io-notice" data-testid="export-profile-notice">
                {exportNotice}
              </div>
            )}
            {restoreError && (
              <div className="validation-error" data-testid="restore-profile-error" role="alert">
                {restoreError}
              </div>
            )}
            {restoreWarnings.length > 0 && (
              <ul className="restore-warnings" data-testid="restore-profile-warnings">
                {restoreWarnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      <main className="dashboard-grid">
        <FeatureSelectionPanel
          profile={profile}
          onUpdateProfile={updateProfile}
          onResetDefault={() => {
            const def = createDefaultProfile();
            setHostInput(def.target.host);
            setPortInput(String(def.target.port));
          }}
        />
        <ResultPanel showSynthetic={showSynthetic} onToggleSynthetic={setShowSynthetic} />
      </main>
    </div>
  );
}
