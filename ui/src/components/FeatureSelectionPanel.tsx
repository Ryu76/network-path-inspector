import { useState } from 'react';
import {
  clearAllFeatures,
  createDefaultProfile,
  DEFAULT_G1_CAPABILITIES,
  estimateProfileDurationMs,
  G1_CONTRACT,
  getFeatureDisabledInfo,
  getGroupSelectionState,
  GROUP_LABELS,
  type Profile,
  selectAllFeatures,
  toggleFeature,
  toggleGroupFeatures,
} from '../domain';

export interface FeatureSelectionPanelProps {
  readonly profile: Profile;
  readonly onUpdateProfile: (next: Profile) => void;
  readonly onResetDefault: () => void;
}

export function FeatureSelectionPanel({
  profile,
  onUpdateProfile,
  onResetDefault,
}: FeatureSelectionPanelProps) {
  const [featureSearch, setFeatureSearch] = useState<string>('');
  const normalizedSearch = featureSearch.trim().toLowerCase();
  const estimatedDurationSec = (estimateProfileDurationMs(profile) / 1000).toFixed(1);

  return (
    <section className="panel feature-panel" aria-labelledby="feature-panel-heading">
      <div className="panel-header-row">
        <div>
          <h2 id="feature-panel-heading" className="panel-title">
            기능 선택 (6개 그룹 · 23개 기능)
          </h2>
          <p className="panel-subtitle" data-testid="selected-feature-count">
            선택된 기능: <strong>{profile.selected_features.length}</strong> /{' '}
            {G1_CONTRACT.features.length}개 · 예상 소요시간(단순 추정치): 약 {estimatedDurationSec}초
          </p>
        </div>
        <div className="bulk-btn-row">
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            data-testid="select-all-btn"
            onClick={() =>
              onUpdateProfile(selectAllFeatures(profile, DEFAULT_G1_CAPABILITIES))
            }
          >
            전체 선택 (안전)
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            data-testid="clear-all-btn"
            onClick={() => onUpdateProfile(clearAllFeatures(profile))}
          >
            전체 해제
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            data-testid="reset-default-btn"
            onClick={() => {
              onResetDefault();
              onUpdateProfile(createDefaultProfile());
            }}
          >
            기본 5개 복원
          </button>
        </div>
      </div>

      <div className="search-bar">
        <input
          type="search"
          data-testid="feature-search-input"
          placeholder="기능 한글명, 영문 ID, 설명으로 검색..."
          value={featureSearch}
          onChange={(e) => setFeatureSearch(e.target.value)}
        />
        {featureSearch && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            data-testid="feature-search-clear-btn"
            onClick={() => setFeatureSearch('')}
          >
            검색 지우기
          </button>
        )}
      </div>

      <div className="group-list">
        {G1_CONTRACT.groups.map((groupId) => {
          const groupMeta = GROUP_LABELS[groupId];
          const groupState = getGroupSelectionState(
            profile,
            groupId,
            DEFAULT_G1_CAPABILITIES,
          );
          const groupFeatures = G1_CONTRACT.features.filter((f) => {
            if (f.group_id !== groupId) {
              return false;
            }
            if (!normalizedSearch) {
              return true;
            }
            const haystack = `${f.feature_id} ${f.label} ${f.description} ${groupMeta.name}`.toLowerCase();
            return haystack.includes(normalizedSearch);
          });

          if (normalizedSearch && groupFeatures.length === 0) {
            return null;
          }

          return (
            <div
              key={groupId}
              className="group-card"
              data-testid={`group-card-${groupId}`}
            >
              <div className="group-card-header">
                <label className="group-checkbox-label">
                  <input
                    type="checkbox"
                    data-testid={`group-checkbox-${groupId}`}
                    data-indeterminate={String(groupState.indeterminate)}
                    aria-checked={
                      groupState.indeterminate ? 'mixed' : groupState.checked
                    }
                    checked={groupState.checked}
                    ref={(el) => {
                      if (el) {
                        el.indeterminate = groupState.indeterminate;
                      }
                    }}
                    onChange={(e) =>
                      onUpdateProfile(
                        toggleGroupFeatures(
                          profile,
                          groupId,
                          e.target.checked,
                          DEFAULT_G1_CAPABILITIES,
                        ),
                      )
                    }
                  />
                  <strong>
                    {groupId} · {groupMeta.name}
                  </strong>
                </label>
                <span
                  className="badge badge-count"
                  data-testid={`group-count-${groupId}`}
                >
                  {groupState.selected_count} / {groupState.total_count} 선택
                </span>
              </div>
              <p className="group-summary-text">{groupMeta.summary}</p>

              <div className="feature-items">
                {groupFeatures.map((feat) => {
                  const isSelected = profile.selected_features.includes(feat.feature_id);
                  const disabledInfo = getFeatureDisabledInfo(
                    feat.feature_id,
                    profile,
                    DEFAULT_G1_CAPABILITIES,
                  );

                  return (
                    <div
                      key={feat.feature_id}
                      className={`feature-item ${disabledInfo.disabled ? 'is-disabled' : ''} ${
                        isSelected ? 'is-selected' : ''
                      }`}
                      data-testid={`feature-row-${feat.feature_id}`}
                    >
                      <div className="feature-item-main">
                        <label className="feature-checkbox-label">
                          <input
                            type="checkbox"
                            data-testid={`feature-checkbox-${feat.feature_id}`}
                            checked={isSelected}
                            disabled={disabledInfo.disabled}
                            onChange={(e) =>
                              onUpdateProfile(
                                toggleFeature(
                                  profile,
                                  feat.feature_id,
                                  e.target.checked,
                                  DEFAULT_G1_CAPABILITIES,
                                ),
                              )
                            }
                          />
                          <span className="feature-name">{feat.label}</span>
                          <code className="code-tag">{feat.feature_id}</code>
                        </label>
                        <div className="feature-badges">
                          {feat.default_selected && (
                            <span className="badge badge-default">기본값</span>
                          )}
                          <span className={`badge badge-cost-${feat.cost_class.toLowerCase()}`}>
                            비용:{feat.cost_class}
                          </span>
                        </div>
                      </div>
                      <p className="feature-desc">{feat.description}</p>
                      {disabledInfo.disabled && disabledInfo.reason && (
                        <div
                          className="disabled-reason-box"
                          data-testid={`feature-disabled-reason-${feat.feature_id}`}
                        >
                          <div>
                            <strong>비활성 사유:</strong> {disabledInfo.reason}
                          </div>
                          {disabledInfo.alternative && <div>{disabledInfo.alternative}</div>}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
