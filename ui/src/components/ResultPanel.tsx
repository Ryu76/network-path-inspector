import { useMemo, useState } from 'react';
import {
  aggregateGroups,
  type EvidenceClassification,
  type FeatureId,
  type FeatureStatus,
  filterResults,
  flattenSessionResults,
  G1_CONTRACT,
  getFeatureDefinition,
  GROUP_LABELS,
  type GroupId,
  type ResultFilters,
  type ResultSortField,
  STATUS_METADATA,
} from '../domain';
import { SYNTHETIC_EXAMPLE_SESSION } from '../fixtures/syntheticFixture';

export type ResultViewTab = 'all' | 'groups' | 'features';

export interface ResultPanelProps {
  readonly showSynthetic: boolean;
  readonly onToggleSynthetic: (enabled: boolean) => void;
}

const CLASSIFICATION_KO: Readonly<Record<EvidenceClassification, string>> = {
  OBSERVED: '관찰 (OBSERVED)',
  INFERRED: '추론 (INFERRED)',
  UNKNOWN: '미확인 (UNKNOWN)',
};

export function ResultPanel({ showSynthetic, onToggleSynthetic }: ResultPanelProps) {
  const [activeTab, setActiveTab] = useState<ResultViewTab>('all');
  const [groupFilter, setGroupFilter] = useState<GroupId | 'ALL'>('ALL');
  const [featureFilter, setFeatureFilter] = useState<FeatureId | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<FeatureStatus | 'ALL'>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<EvidenceClassification | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortBy, setSortBy] = useState<ResultSortField>('default');

  const allResults = useMemo(
    () => (showSynthetic ? flattenSessionResults(SYNTHETIC_EXAMPLE_SESSION) : []),
    [showSynthetic],
  );

  const filters: ResultFilters = useMemo(
    () => ({
      group_id: groupFilter,
      feature_id: featureFilter,
      status: statusFilter,
      classification: classificationFilter,
      search: searchQuery,
      sort_by: sortBy,
    }),
    [groupFilter, featureFilter, statusFilter, classificationFilter, searchQuery, sortBy],
  );

  const filteredResults = useMemo(
    () => filterResults(allResults, filters),
    [allResults, filters],
  );

  const groupAggregations = useMemo(
    () => aggregateGroups(allResults),
    [allResults],
  );

  const statusTotals = useMemo(() => {
    const counts: Record<FeatureStatus, number> = {
      PASS: 0,
      FAIL: 0,
      WARN: 0,
      SKIPPED_BY_USER: 0,
      UNAVAILABLE: 0,
      ERROR: 0,
      CANCELLED: 0,
    };
    for (const item of allResults) {
      counts[item.status] += 1;
    }
    return counts;
  }, [allResults]);

  const handleResetFilters = () => {
    setGroupFilter('ALL');
    setFeatureFilter('ALL');
    setStatusFilter('ALL');
    setClassificationFilter('ALL');
    setSearchQuery('');
    setSortBy('default');
  };

  return (
    <section className="panel result-panel" aria-labelledby="result-panel-heading">
      <div className="panel-header-row">
        <div>
          <h2 id="result-panel-heading" className="panel-title">
            진단 결과 조회 · 상태 분리
          </h2>
          <p className="panel-subtitle">
            전체 · 그룹별 · 기능별 탭 조회 및 7종 결과 상태(PASS/FAIL 외 SKIPPED·UNAVAILABLE·ERROR·CANCELLED) 분리
          </p>
        </div>
        <label className="synthetic-switch-label">
          <input
            type="checkbox"
            data-testid="synthetic-fixture-toggle"
            checked={showSynthetic}
            onChange={(e) => onToggleSynthetic(e.target.checked)}
          />
          <span>합성 예시 보기</span>
        </label>
      </div>

      {showSynthetic ? (
        <div
          className="banner banner-synthetic"
          data-testid="synthetic-fixture-banner"
          role="status"
        >
          <strong>[합성 예시 데이터 (SYNTHETIC FIXTURE) 표시 중]</strong> 실제 네트워크 프로브·패킷 캡처
          측정 결과가 아니며, G1 UI의 상태 분리·집계·다차원 필터 동작을 검증하기 위한 합성 예시(
          <code>synthetic_fixture=true</code>)입니다.
        </div>
      ) : (
        <div
          className="banner banner-empty-state"
          data-testid="empty-results-state"
          role="status"
        >
          <strong>초기 결과 상태: EMPTY (실행된 진단 없음 · PASS 아님)</strong>
          <span>
            G1 단계에서는 실제 진단 엔진이 미연결 상태이므로 자동 실행이나 가짜 PASS 결과를 생성하지 않습니다.
            결과 탭·필터·상태 분리 UI를 확인하려면 우측 상단의 <strong>‘합성 예시 보기’</strong> 스위치를 켜십시오.
          </span>
        </div>
      )}

      <div className="tabs-row" role="tablist" aria-label="결과 보기 방식 탭">
        <button
          type="button"
          role="tab"
          data-testid="result-tab-all"
          aria-selected={activeTab === 'all'}
          className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
          onClick={() => setActiveTab('all')}
        >
          전체 ({allResults.length})
        </button>
        <button
          type="button"
          role="tab"
          data-testid="result-tab-groups"
          aria-selected={activeTab === 'groups'}
          className={`tab-btn ${activeTab === 'groups' ? 'active' : ''}`}
          onClick={() => setActiveTab('groups')}
        >
          그룹별 (6)
        </button>
        <button
          type="button"
          role="tab"
          data-testid="result-tab-features"
          aria-selected={activeTab === 'features'}
          className={`tab-btn ${activeTab === 'features' ? 'active' : ''}`}
          onClick={() => setActiveTab('features')}
        >
          기능별 ({filteredResults.length})
        </button>
      </div>

      <div className="filter-bar" aria-label="결과 다차원 필터">
        <div className="filter-field">
          <label htmlFor="filter-group-select">그룹 필터</label>
          <select
            id="filter-group-select"
            data-testid="filter-group-select"
            value={groupFilter}
            onChange={(e) => setGroupFilter(e.target.value as GroupId | 'ALL')}
          >
            <option value="ALL">전체 그룹 (6)</option>
            {G1_CONTRACT.groups.map((gid) => (
              <option key={gid} value={gid}>
                {gid} · {GROUP_LABELS[gid].name}
              </option>
            ))}
          </select>
        </div>

        <div className="filter-field">
          <label htmlFor="filter-feature-select">기능 필터</label>
          <select
            id="filter-feature-select"
            data-testid="filter-feature-select"
            value={featureFilter}
            onChange={(e) => setFeatureFilter(e.target.value as FeatureId | 'ALL')}
          >
            <option value="ALL">전체 기능 (23)</option>
            {G1_CONTRACT.features.map((feat) => (
              <option key={feat.feature_id} value={feat.feature_id}>
                {feat.label} ({feat.feature_id})
              </option>
            ))}
          </select>
        </div>

        <div className="filter-field">
          <label htmlFor="filter-status-select">상태 필터</label>
          <select
            id="filter-status-select"
            data-testid="filter-status-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as FeatureStatus | 'ALL')}
          >
            <option value="ALL">전체 상태 (7)</option>
            {G1_CONTRACT.statuses.map((st) => (
              <option key={st} value={st}>
                {st} ({STATUS_METADATA[st].koreanLabel})
              </option>
            ))}
          </select>
        </div>

        <div className="filter-field">
          <label htmlFor="filter-classification-select">근거 수준</label>
          <select
            id="filter-classification-select"
            data-testid="filter-classification-select"
            value={classificationFilter}
            onChange={(e) =>
              setClassificationFilter(e.target.value as EvidenceClassification | 'ALL')
            }
          >
            <option value="ALL">전체 근거</option>
            <option value="OBSERVED">OBSERVED (관찰)</option>
            <option value="INFERRED">INFERRED (추론)</option>
            <option value="UNKNOWN">UNKNOWN (미확인)</option>
          </select>
        </div>

        <div className="filter-field">
          <label htmlFor="filter-sort-select">정렬 기준</label>
          <select
            id="filter-sort-select"
            data-testid="filter-sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as ResultSortField)}
          >
            <option value="default">기본 계약 순서</option>
            <option value="status">위험/상태 우선순위</option>
            <option value="group">그룹 순서</option>
            <option value="feature">기능명 가나다순</option>
            <option value="duration_ms">소요시간순</option>
            <option value="classification">근거 수준순</option>
          </select>
        </div>

        <div className="filter-field filter-search-field">
          <label htmlFor="filter-search-input">결과 검색</label>
          <div className="input-with-btn">
            <input
              id="filter-search-input"
              data-testid="filter-search-input"
              type="search"
              placeholder="기능 ID, 한글명, 상태, 한계점 검색..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button
              type="button"
              data-testid="filter-reset-btn"
              className="btn btn-secondary btn-sm"
              onClick={handleResetFilters}
            >
              필터 초기화
            </button>
          </div>
        </div>
      </div>

      <div className="status-summary-grid" aria-label="7종 상태 분리 집계">
        {G1_CONTRACT.statuses.map((st) => {
          const meta = STATUS_METADATA[st];
          const count = statusTotals[st];
          return (
            <div
              key={st}
              data-testid={`status-card-${st}`}
              className={`status-summary-card status-tone-${st.toLowerCase()}`}
            >
              <div className="status-card-top">
                <span className="status-icon" aria-hidden="true">
                  {meta.icon}
                </span>
                <span className="status-code">{meta.shortText}</span>
                <strong className="status-count" data-testid={`status-count-${st}`}>
                  {count}
                </strong>
              </div>
              <div className="status-ko">{meta.koreanLabel}</div>
            </div>
          );
        })}
      </div>

      {activeTab === 'all' && (
        <div className="tab-panel" data-testid="tab-panel-all">
          <h3 className="section-subtitle">그룹 요약 상태 (빈 결과는 EMPTY · PASS 위장 금지)</h3>
          <div className="group-mini-grid">
            {groupAggregations.map((agg) => (
              <div
                key={agg.group_id}
                className={`group-mini-card status-border-${agg.summary_status.toLowerCase()}`}
                data-testid={`all-tab-group-${agg.group_id}`}
              >
                <div className="group-mini-header">
                  <strong>
                    {agg.group_id} · {agg.label}
                  </strong>
                  <span
                    className={`badge badge-status-${agg.summary_status.toLowerCase()}`}
                    data-testid={`group-summary-status-${agg.group_id}`}
                  >
                    {agg.summary_status === 'EMPTY'
                      ? 'EMPTY (미실행)'
                      : `${STATUS_METADATA[agg.summary_status].icon} ${agg.summary_status}`}
                  </span>
                </div>
                <div className="group-mini-meta">
                  결과 {agg.result_count} / 정의 {agg.total_defined_features}개
                </div>
              </div>
            ))}
          </div>

          {showSynthetic ? (
            <div className="findings-box" data-testid="synthetic-findings-list">
              <h3 className="section-subtitle">
                합성 예시 판정 요약 (관찰 OBSERVED / 추론 INFERRED / 미확인 UNKNOWN 분리)
              </h3>
              {SYNTHETIC_EXAMPLE_SESSION.findings.map((finding, idx) => (
                <article key={idx} className="finding-card">
                  <div className="finding-header">
                    <span className="badge badge-classification">
                      {CLASSIFICATION_KO[finding.classification]}
                    </span>
                    <span className="badge badge-synthetic-tag">합성 예시 (SYNTHETIC)</span>
                    <span className="finding-confidence">신뢰도: {finding.confidence}</span>
                  </div>
                  <p className="finding-statement">{finding.statement}</p>
                  {finding.limitations.length > 0 && (
                    <p className="finding-note">한계: {finding.limitations.join(' / ')}</p>
                  )}
                </article>
              ))}
            </div>
          ) : (
            <div className="empty-placeholder" data-testid="all-tab-empty-notice">
              실행된 세션이 없어 판정 요약(Findings) 및 기능 결과가 비어 있습니다 (상태: EMPTY).
            </div>
          )}
        </div>
      )}

      {activeTab === 'groups' && (
        <div className="tab-panel" data-testid="tab-panel-groups">
          <div className="group-agg-list">
            {groupAggregations.map((agg) => (
              <article
                key={agg.group_id}
                className="group-agg-card"
                data-testid={`group-agg-card-${agg.group_id}`}
              >
                <div className="group-agg-header">
                  <div>
                    <strong>
                      {agg.group_id} · {agg.label}
                    </strong>
                    <p className="group-agg-desc">{agg.description}</p>
                  </div>
                  <span
                    className={`badge badge-status-${agg.summary_status.toLowerCase()}`}
                    data-testid={`group-summary-status-${agg.group_id}`}
                  >
                    {agg.summary_status === 'EMPTY'
                      ? 'EMPTY (미실행 · PASS 아님)'
                      : `${STATUS_METADATA[agg.summary_status].icon} ${agg.summary_status} (${STATUS_METADATA[agg.summary_status].koreanLabel})`}
                  </span>
                </div>
                <div className="group-agg-counts">
                  <span>정의 기능: {agg.total_defined_features}개</span>
                  <span>수집 결과: {agg.result_count}건</span>
                  <span>PASS: {agg.counts.PASS}</span>
                  <span>FAIL: {agg.counts.FAIL}</span>
                  <span>WARN: {agg.counts.WARN}</span>
                  <span>SKIPPED: {agg.counts.SKIPPED_BY_USER}</span>
                  <span>UNAVAILABLE: {agg.counts.UNAVAILABLE}</span>
                  <span>ERROR: {agg.counts.ERROR}</span>
                  <span>CANCELLED: {agg.counts.CANCELLED}</span>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'features' && (
        <div className="tab-panel" data-testid="tab-panel-features">
          <div className="result-count-bar" data-testid="filtered-result-count">
            필터링된 기능 결과: <strong>{filteredResults.length}</strong> / 전체 {allResults.length}건
          </div>

          {filteredResults.length === 0 ? (
            <div className="empty-placeholder" data-testid="feature-results-empty">
              {showSynthetic
                ? '현재 선택한 필터 조건에 일치하는 기능 결과가 없습니다.'
                : '실행된 진단 결과가 없습니다 (초기 상태: EMPTY — PASS 아님).'}
            </div>
          ) : (
            <div className="feature-result-list">
              {filteredResults.map((item) => {
                const def = getFeatureDefinition(item.feature_id);
                const statusMeta = STATUS_METADATA[item.status];
                return (
                  <article
                    key={item.feature_id}
                    className="feature-result-card"
                    data-testid={`result-item-${item.feature_id}`}
                  >
                    <div className="feature-result-header">
                      <div>
                        <strong>{def?.label ?? item.feature_id}</strong>{' '}
                        <code className="code-tag">{item.feature_id}</code>{' '}
                        <span className="badge badge-group">
                          {item.group_id} · {GROUP_LABELS[item.group_id].name}
                        </span>
                      </div>
                      <div className="feature-result-badges">
                        {showSynthetic && (
                          <span className="badge badge-synthetic-tag">합성 예시</span>
                        )}
                        <span className="badge badge-classification">
                          {item.classification
                            ? CLASSIFICATION_KO[item.classification]
                            : CLASSIFICATION_KO.UNKNOWN}
                        </span>
                        <span
                          className={`badge badge-status-${item.status.toLowerCase()}`}
                          data-testid={`result-item-status-${item.feature_id}`}
                        >
                          {statusMeta.icon} {statusMeta.shortText} ({statusMeta.koreanLabel})
                        </span>
                      </div>
                    </div>
                    <div className="feature-result-meta">
                      <span>
                        소요시간: {item.duration_ms !== null ? `${item.duration_ms} ms` : '미실행 (-)'}
                      </span>
                      {item.error_code !== null && <span>오류 코드: {item.error_code}</span>}
                    </div>
                    {item.limitations.length > 0 && (
                      <ul className="feature-result-notes">
                        {item.limitations.map((lim, i) => (
                          <li key={i}>해석 한계: {lim}</li>
                        ))}
                      </ul>
                    )}
                    {item.next_checks.length > 0 && (
                      <ul className="feature-result-notes next-checks">
                        {item.next_checks.map((chk, i) => (
                          <li key={i}>권장 확인: {chk}</li>
                        ))}
                      </ul>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
