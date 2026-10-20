import {
  type ConfidenceLevel,
  type ContractFeatureDefinition,
  type ContractPresetId,
  type CostClass,
  type DiagnosticMode,
  type EvidenceClassification,
  type EvidenceKind,
  type FeatureId,
  type FeatureStatus,
  FEATURE_ESTIMATED_DURATION_MS,
  G1_CONTRACT,
  GROUP_LABELS,
  type GroupId,
  type HostRole,
  type PermissionLevel,
  type PresetSelectionId,
  STATUS_METADATA,
  type TcpOutcome,
  deepFreeze,
} from './contracts/g1Contract';

export {
  type ConfidenceLevel,
  type ContractFeatureDefinition,
  type ContractPresetId,
  type CostClass,
  type DiagnosticMode,
  type EvidenceClassification,
  type EvidenceKind,
  type FeatureId,
  type FeatureStatus,
  FEATURE_ESTIMATED_DURATION_MS,
  G1_CONTRACT,
  GROUP_LABELS,
  type GroupId,
  type HostRole,
  type PermissionLevel,
  type PresetSelectionId,
  STATUS_METADATA,
  type TcpOutcome,
  deepFreeze,
};

export interface Target {
  host: string;
  port: number;
  protocol: 'TCP';
}

export interface Limits {
  tcp_timeout_ms: number;
  max_hops: number;
  retries: number;
  max_concurrent_tcp: number;
  capture_duration_secs: number;
  capture_max_bytes: number;
  log_retention_days: number;
  ui_updates_per_second: number;
}

export interface Profile {
  schema_version: '1.1';
  profile_id: string;
  label: string;
  mode: DiagnosticMode;
  selected_features: FeatureId[];
  capture_approved: boolean;
  target: Target;
  limits: Limits;
}

export interface RestoredProfile extends Profile {
  ignored_features: string[];
  stripped_high_cost_features: FeatureId[];
  restore_warnings: string[];
  legacy_migrated: boolean;
  legacy_raw_input: unknown;
}

export interface Evidence {
  evidence_id: string;
  kind: EvidenceKind;
  artifact_path: string | null;
  synthetic: boolean;
}

export interface Finding {
  classification: EvidenceClassification;
  statement: string;
  evidence_ids: string[];
  confidence: ConfidenceLevel;
  limitations: string[];
  next_checks: string[];
}

export interface FeatureResult {
  feature_id: FeatureId;
  group_id: GroupId;
  status: FeatureStatus;
  classification: EvidenceClassification | null;
  evidence_ids: string[];
  started_at_utc: string | null;
  ended_at_utc: string | null;
  duration_ms: number | null;
  error_code: number | null;
  limitations: string[];
  next_checks: string[];
}

export interface FilterableFeatureResult extends FeatureResult {
  session_id?: string;
  mode?: DiagnosticMode;
  host_role?: HostRole | null;
  target?: Target | string;
}

export interface ResourceMetrics {
  peak_rss_bytes: number | null;
  avg_cpu_percent: number | null;
  capture_drops: number | null;
}

export interface Session {
  schema_version: '1.1';
  session_id: string;
  mode: DiagnosticMode;
  host_role: HostRole | null;
  started_at_utc: string;
  timezone_offset_minutes: number | null;
  clock_offset_ms: number | null;
  clock_uncertainty_ms: number | null;
  profile: Profile;
  evidence: Evidence[];
  feature_results: FeatureResult[];
  findings: Finding[];
  limitations: string[];
  resource_metrics: ResourceMetrics;
  synthetic_fixture?: boolean;
  raw_legacy_input?: unknown;
}

export interface RuntimeCapabilityState {
  readonly validated_tcp_ttl_backend: boolean;
  readonly npcap_installed: boolean;
  readonly capture_privilege_available: boolean;
}

/**
 * G1 기본 런타임 역량 상태:
 * 실제 프로브·캡처·드라이버가 연결되기 전이므로 TCP TTL 백엔드는 미검증(false)입니다.
 */
export const DEFAULT_G1_CAPABILITIES: RuntimeCapabilityState = deepFreeze({
  validated_tcp_ttl_backend: false,
  npcap_installed: false,
  capture_privilege_available: false,
});

export interface FeatureDisabledInfo {
  readonly disabled: boolean;
  readonly reason: string | null;
  readonly alternative: string | null;
  readonly requiresConsent: boolean;
}

export type GroupSummaryStatus = FeatureStatus | 'EMPTY';

export interface GroupAggregation {
  readonly group_id: GroupId;
  readonly label: string;
  readonly description: string;
  readonly total_defined_features: number;
  readonly result_count: number;
  readonly has_executed: boolean;
  readonly summary_status: GroupSummaryStatus;
  readonly counts: Readonly<Record<FeatureStatus, number>>;
  readonly items: FeatureResult[];
}

export type ResultSortField =
  | 'default'
  | 'group'
  | 'feature'
  | 'status'
  | 'duration_ms'
  | 'started_at_utc'
  | 'classification';

export type SortDirection = 'asc' | 'desc';

export interface ResultFilters {
  group_id?: GroupId | 'ALL' | '';
  group?: GroupId | 'ALL' | '';
  feature_id?: FeatureId | 'ALL' | '';
  feature?: FeatureId | 'ALL' | '';
  status?: FeatureStatus | 'ALL' | '';
  host_role?: HostRole | 'ALL' | '';
  hostRole?: HostRole | 'ALL' | '';
  mode?: DiagnosticMode | 'ALL' | '';
  session_id?: string;
  session?: string;
  date?: string;
  date_from?: string;
  dateFrom?: string;
  date_to?: string;
  dateTo?: string;
  target?: string;
  classification?: EvidenceClassification | 'ALL' | '';
  evidence_level?: EvidenceClassification | 'ALL' | '';
  evidenceLevel?: EvidenceClassification | 'ALL' | '';
  search?: string;
  query?: string;
  sort_by?: ResultSortField | 'duration' | 'date' | 'time' | 'evidence_level';
  sortBy?: ResultSortField | 'duration' | 'date' | 'time' | 'evidence_level';
  sort_order?: SortDirection;
  sortOrder?: SortDirection;
}

export interface TargetValidationResult {
  readonly valid: boolean;
  readonly hostError: string | null;
  readonly portError: string | null;
}

export interface LimitsValidationResult {
  readonly valid: boolean;
  readonly timeoutError: string | null;
  readonly maxHopsError: string | null;
}

export interface ExecutionSelectionState {
  readonly is_running: boolean;
  readonly current_session_profile: Readonly<Profile> | null;
  readonly active_profile: Profile;
  readonly queued_next_profile: Profile | null;
}

const KNOWN_FEATURE_IDS = new Set<FeatureId>(
  G1_CONTRACT.features.map((f) => f.feature_id),
);

const FEATURE_MAP = new Map<FeatureId, ContractFeatureDefinition>(
  G1_CONTRACT.features.map((f) => [f.feature_id, f]),
);

const KNOWN_MODES = new Set<DiagnosticMode>(G1_CONTRACT.modes);
const KNOWN_GROUPS = new Set<GroupId>(G1_CONTRACT.groups);
const KNOWN_STATUSES = new Set<FeatureStatus>(G1_CONTRACT.statuses);

/**
 * 참조 공유로 인한 상태 오염을 막기 위한 깊은 복사(Deep Clone) 함수
 */
export function deepClone<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => deepClone(item)) as unknown as T;
  }
  const cloned: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>)) {
    cloned[key] = deepClone((value as Record<string, unknown>)[key]);
  }
  return cloned as T;
}

/**
 * 알려진 계약 기능 ID인지 판별합니다.
 */
export function isKnownFeatureId(id: unknown): id is FeatureId {
  return typeof id === 'string' && KNOWN_FEATURE_IDS.has(id as FeatureId);
}

/**
 * 기능 정의를 조회합니다.
 */
export function getFeatureDefinition(id: FeatureId): ContractFeatureDefinition | undefined {
  return FEATURE_MAP.get(id);
}

/**
 * 계약에 정의된 순서대로 기능 ID 배열을 정렬 및 중복 제거합니다.
 */
function normalizeFeatureList(ids: Iterable<FeatureId>): FeatureId[] {
  const set = new Set<FeatureId>(ids);
  return G1_CONTRACT.features
    .map((f) => f.feature_id)
    .filter((id) => set.has(id));
}

/**
 * 개별 기능의 비활성 여부와 사유·대안을 반환합니다.
 * - tcp_traceroute: 검증된 TCP TTL 백엔드 및 캡처 요건이 충족되기 전까지 비활성(UNAVAILABLE)
 * - packet_capture: 별도의 명시적 동의(capture_approved)가 체크되기 전까지 선택 불가
 */
export function getFeatureDisabledInfo(
  featureId: FeatureId,
  profile: Pick<Profile, 'capture_approved' | 'mode'>,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): FeatureDisabledInfo {
  const def = FEATURE_MAP.get(featureId);
  if (!def) {
    return {
      disabled: true,
      reason: '계약에 정의되지 않은 알 수 없는 기능 ID입니다.',
      alternative: '지원되는 23개 표준 진단 기능을 선택하십시오.',
      requiresConsent: false,
    };
  }

  if (!def.supported_modes.includes(profile.mode)) {
    return {
      disabled: true,
      reason: `현재 진단 모드(${profile.mode})에서 지원되지 않는 기능입니다.`,
      alternative: '지원 모드로 전환 후 선택하십시오.',
      requiresConsent: false,
    };
  }

  if (featureId === 'tcp_traceroute' && !capabilities.validated_tcp_ttl_backend) {
    return {
      disabled: true,
      reason: '검증된 TCP TTL 프로브 백엔드 및 캡처 권한 미확보 (G3/G4 게이트 검증 전 미지원)',
      alternative: '대안: ICMP 경로 추적(icmp_traceroute) 및 라우팅 테이블(route_table)·TCP 연결(tcp_connect) 조합 사용 (ICMP 결과를 TCP 결과로 위장하지 않음)',
      requiresConsent: false,
    };
  }

  if (featureId === 'packet_capture' && !profile.capture_approved) {
    return {
      disabled: true,
      reason: '패킷 캡처 별도 명시적 동의가 체크되지 않았습니다 (프리셋·전체선택·복원으로 자동 승인 불가)',
      alternative: '대안: 상단/기능 패널의 패킷 캡처 별도 동의 체크박스를 먼저 승인하거나 기본 소켓·라우팅 진단을 사용하십시오.',
      requiresConsent: true,
    };
  }

  return {
    disabled: false,
    reason: null,
    alternative: null,
    requiresConsent: featureId === 'packet_capture',
  };
}

/**
 * 기능이 현재 상태에서 선택/활성화 불가능한지 확인합니다.
 */
export function isFeatureDisabled(
  featureId: FeatureId,
  profile: Pick<Profile, 'capture_approved' | 'mode'>,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): boolean {
  return getFeatureDisabledInfo(featureId, profile, capabilities).disabled;
}

/**
 * 첫 실행 기본 프로파일을 생성합니다.
 * 계약의 quick-default(5개 기능: tcp_connect, icmp_ping, nic_inventory, route_table, result_json)와 일치합니다.
 */
export function createDefaultProfile(): Profile {
  const defaultFeatures = G1_CONTRACT.features
    .filter((f) => f.default_selected)
    .map((f) => f.feature_id);

  return {
    schema_version: '1.1',
    profile_id: 'quick-default',
    label: '빠른 진단 기본 프로파일',
    mode: 'standalone',
    selected_features: normalizeFeatureList(defaultFeatures),
    capture_approved: false,
    target: {
      host: '127.0.0.1',
      port: 1526,
      protocol: 'TCP',
    },
    limits: {
      tcp_timeout_ms: 5000,
      max_hops: 30,
      retries: 0,
      max_concurrent_tcp: 4,
      capture_duration_secs: 30,
      capture_max_bytes: 52428800,
      log_retention_days: 30,
      ui_updates_per_second: 4,
    },
  };
}

const PRESET_ALIAS_MAP: Readonly<Record<string, ContractPresetId>> = {
  'quick-default': 'quick-default',
  quick: 'quick-default',
  빠른: 'quick-default',
  '빠른 진단': 'quick-default',
  'path-default': 'path-default',
  path: 'path-default',
  경로: 'path-default',
  '경로 진단': 'path-default',
  'precise-default': 'precise-default',
  precise: 'precise-default',
  정밀: 'precise-default',
  '정밀 증빙': 'precise-default',
  'paired-default': 'paired-default',
  paired: 'paired-default',
  양방향: 'paired-default',
  '양방향 비교': 'paired-default',
};

const PRESET_KOREAN_LABELS: Readonly<Record<ContractPresetId, string>> = {
  'quick-default': '빠른 진단 프로파일',
  'path-default': '경로 진단 프로파일',
  'precise-default': '정밀 증빙 프로파일',
  'paired-default': '양방향 비교 프로파일',
};

/**
 * 프리셋을 적용한 새 프로파일 복사본을 반환합니다.
 * 안전 규칙:
 * - 프리셋 선택은 절대 패킷 캡처 동의(capture_approved)를 자동 부여하지 않습니다.
 * - 비활성 기능(tcp_traceroute) 및 미승인 고비용 기능(packet_capture)은 선택 목록에 자동 포함되지 않습니다.
 */
export function selectPreset(
  profile: Profile,
  presetId: PresetSelectionId | string,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): Profile {
  const cloned = deepClone(profile);
  if (presetId === 'custom' || presetId === '사용자 정의') {
    cloned.profile_id = 'custom';
    cloned.label = '사용자 정의 프로파일';
    cloned.capture_approved = false;
    cloned.selected_features = normalizeFeatureList(
      cloned.selected_features.filter(
        (id) => isKnownFeatureId(id) && !isFeatureDisabled(id, { ...cloned, capture_approved: false }, capabilities),
      ),
    );
    return cloned;
  }

  const resolvedId = PRESET_ALIAS_MAP[presetId];
  if (!resolvedId) {
    throw new Error(`알 수 없는 프리셋 ID입니다: ${String(presetId)}`);
  }

  const rawPresetFeatures = G1_CONTRACT.presets[resolvedId];
  const nextMode: DiagnosticMode = resolvedId === 'paired-default' ? 'paired_offline' : cloned.mode;

  // 프리셋은 절대 capture_approved를 자동 활성화하지 않으며,
  // 고비용(HIGH) 또는 비활성 기능을 자동으로 켜지 않습니다.
  const nextBase: Pick<Profile, 'capture_approved' | 'mode'> = {
    capture_approved: false,
    mode: nextMode,
  };

  const filteredFeatures = rawPresetFeatures.filter((featureId) => {
    const def = FEATURE_MAP.get(featureId);
    if (!def) {
      return false;
    }
    if (def.cost_class === 'HIGH') {
      return false;
    }
    return !isFeatureDisabled(featureId, nextBase, capabilities);
  });

  return {
    ...cloned,
    profile_id: resolvedId,
    label: PRESET_KOREAN_LABELS[resolvedId],
    mode: nextMode,
    capture_approved: false,
    selected_features: normalizeFeatureList(filteredFeatures),
  };
}

/**
 * 개별 기능 선택을 토글하거나 지정된 선택 상태로 변경한 새 프로파일을 반환합니다.
 * 비활성화된 기능(예: 미검증 tcp_traceroute, 동의 없는 packet_capture)은 선택 상태로 위장되지 않습니다.
 */
export function toggleFeature(
  profile: Profile,
  id: FeatureId | string,
  selected?: boolean,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): Profile {
  const cloned = deepClone(profile);
  if (!isKnownFeatureId(id)) {
    return cloned;
  }

  const currentlySelected = cloned.selected_features.includes(id);
  const nextSelected = selected === undefined ? !currentlySelected : Boolean(selected);

  if (nextSelected) {
    if (isFeatureDisabled(id, cloned, capabilities)) {
      return cloned;
    }
    if (!currentlySelected) {
      cloned.selected_features = normalizeFeatureList([...cloned.selected_features, id]);
    }
  } else {
    cloned.selected_features = cloned.selected_features.filter((item) => item !== id);
  }

  return cloned;
}

/**
 * 패킷 캡처 별도 명시적 동의 상태를 변경합니다.
 * 동의를 해제하면 packet_capture 기능 선택도 즉시 해제됩니다.
 */
export function setCaptureConsent(profile: Profile, approved: boolean): Profile {
  const cloned = deepClone(profile);
  cloned.capture_approved = Boolean(approved);
  if (!cloned.capture_approved) {
    cloned.selected_features = cloned.selected_features.filter((id) => id !== 'packet_capture');
  }
  return cloned;
}

/**
 * 전체 선택:
 * 활성화 가능한 일반(LOW/MEDIUM) 기능만 선택하며,
 * 위험/고비용(HIGH) 기능(packet_capture, tcp_traceroute) 및 비활성 기능은 절대 자동 활성화하지 않습니다.
 */
export function selectAllFeatures(
  profile: Profile,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): Profile {
  const cloned = deepClone(profile);
  const safeSelectable = G1_CONTRACT.features
    .filter((f) => f.cost_class !== 'HIGH' && !isFeatureDisabled(f.feature_id, cloned, capabilities))
    .map((f) => f.feature_id);

  cloned.selected_features = normalizeFeatureList(safeSelectable);
  return cloned;
}

/**
 * 전체 선택 해제(초기화): 모든 기능 선택을 비우고 캡처 동의를 해제합니다.
 */
export function clearAllFeatures(profile: Profile): Profile {
  const cloned = deepClone(profile);
  cloned.selected_features = [];
  cloned.capture_approved = false;
  return cloned;
}

/**
 * 그룹 단위 전체 선택/해제:
 * 그룹 선택 시 해당 그룹 내 비활성/고위험(HIGH) 기능을 제외한 선택 가능 기능을 모두 선택합니다.
 */
export function toggleGroupFeatures(
  profile: Profile,
  groupId: GroupId,
  selected: boolean,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): Profile {
  const cloned = deepClone(profile);
  if (!KNOWN_GROUPS.has(groupId)) {
    return cloned;
  }

  const groupFeatures = G1_CONTRACT.features.filter((f) => f.group_id === groupId);
  const groupIds = new Set<FeatureId>(groupFeatures.map((f) => f.feature_id));

  if (selected) {
    const safeGroupFeatures = groupFeatures
      .filter((f) => f.cost_class !== 'HIGH' && !isFeatureDisabled(f.feature_id, cloned, capabilities))
      .map((f) => f.feature_id);
    cloned.selected_features = normalizeFeatureList([
      ...cloned.selected_features,
      ...safeGroupFeatures,
    ]);
  } else {
    cloned.selected_features = cloned.selected_features.filter((id) => !groupIds.has(id));
  }

  return cloned;
}

export interface GroupSelectionState {
  readonly group_id: GroupId;
  readonly total_count: number;
  readonly selectable_count: number;
  readonly selected_count: number;
  readonly checked: boolean;
  readonly indeterminate: boolean;
}

/**
 * 특정 그룹의 선택/부분선택(indeterminate) 상태를 계산합니다.
 */
export function getGroupSelectionState(
  profile: Profile,
  groupId: GroupId,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): GroupSelectionState {
  const groupFeatures = G1_CONTRACT.features.filter((f) => f.group_id === groupId);
  const selectedSet = new Set<FeatureId>(profile.selected_features);

  const safeSelectableFeatures = groupFeatures.filter(
    (f) => f.cost_class !== 'HIGH' && !isFeatureDisabled(f.feature_id, profile, capabilities),
  );
  const selectedInGroup = groupFeatures.filter((f) => selectedSet.has(f.feature_id));

  const allSafeSelected =
    safeSelectableFeatures.length > 0 &&
    safeSelectableFeatures.every((f) => selectedSet.has(f.feature_id));

  const checked = allSafeSelected && selectedInGroup.length >= safeSelectableFeatures.length;
  const indeterminate = selectedInGroup.length > 0 && !checked;

  return {
    group_id: groupId,
    total_count: groupFeatures.length,
    selectable_count: safeSelectableFeatures.length,
    selected_count: selectedInGroup.length,
    checked,
    indeterminate,
  };
}

/**
 * 현재 프로파일과 일치하는 프리셋 ID를 판별합니다 (일치하는 프리셋이 없으면 'custom' 반환).
 */
export function detectActivePresetId(
  profile: Profile,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): PresetSelectionId {
  if (profile.capture_approved) {
    return 'custom';
  }
  const currentKey = normalizeFeatureList(profile.selected_features).join(',');
  const presetIds: ContractPresetId[] = [
    'quick-default',
    'path-default',
    'precise-default',
    'paired-default',
  ];

  for (const presetId of presetIds) {
    const presetProfile = selectPreset(profile, presetId, capabilities);
    if (normalizeFeatureList(presetProfile.selected_features).join(',') === currentKey) {
      return presetId;
    }
  }
  return 'custom';
}

/**
 * 선택된 기능들의 예상 소요시간(단순 추정치, 실측 아님)을 합산합니다.
 */
export function estimateProfileDurationMs(profile: Pick<Profile, 'selected_features'>): number {
  let total = 0;
  for (const id of profile.selected_features) {
    if (isKnownFeatureId(id)) {
      total += FEATURE_ESTIMATED_DURATION_MS[id] ?? 0;
    }
  }
  return total;
}

/**
 * 대상 호스트/포트 입력값을 검증합니다.
 * 계약 규칙: nonempty IP/domain string, no URI/path/credentials/CIDR/list; port integer 1..65535
 */
export function validateTarget(target: Partial<Target> | null | undefined): TargetValidationResult {
  if (!target || typeof target !== 'object') {
    return {
      valid: false,
      hostError: '대상 호스트 정보가 없습니다.',
      portError: '대상 포트 정보가 없습니다.',
    };
  }

  let hostError: string | null = null;
  const rawHost = typeof target.host === 'string' ? target.host.trim() : '';

  if (!rawHost) {
    hostError = '대상 IP 또는 도메인을 입력하십시오.';
  } else if (rawHost.includes('://')) {
    hostError = 'URI 스킴(http:// 등)을 제외한 순수 IP 또는 도메인만 입력하십시오.';
  } else if (rawHost.includes('@')) {
    hostError = '계정/자격증명(@)을 포함할 수 없습니다.';
  } else if (rawHost.includes('/')) {
    hostError = '경로(/) 또는 CIDR 대역 표기(/24 등)는 허용되지 않습니다 (단일 대상만 허용).';
  } else if (/[\s,;]/.test(rawHost)) {
    hostError = '복수 대상 목록이나 공백은 허용되지 않습니다 (단일 호스트만 입력).';
  } else if (!rawHost.includes('::') && rawHost.split(':').length === 2 && /:\d+$/.test(rawHost)) {
    hostError = '호스트 입력란에 포트를 함께 적지 마십시오 (TCP 포트는 별도 입력란 사용).';
  } else if (/^\d+\.\d+\.\d+\.\d+$/.test(rawHost)) {
    const octets = rawHost.split('.').map((part) => Number(part));
    if (octets.some((num) => !Number.isInteger(num) || num < 0 || num > 255)) {
      hostError = '유효하지 않은 IPv4 주소 형식입니다 (각 옥텟은 0~255).';
    }
  } else if (!rawHost.includes(':') && !/^[a-zA-Z0-9.-]+$/.test(rawHost)) {
    hostError = '유효한 IPv4, IPv6 또는 도메인 이름을 입력하십시오.';
  }

  let portError: string | null = null;
  const port = target.port;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
    portError = 'TCP 포트는 1부터 65535 사이의 정수여야 합니다.';
  }

  return {
    valid: hostError === null && portError === null,
    hostError,
    portError,
  };
}

/**
 * 타임아웃 및 최대 HOP 제한 설정을 검증합니다.
 */
export function validateLimits(limits: Partial<Limits> | null | undefined): LimitsValidationResult {
  if (!limits || typeof limits !== 'object') {
    return {
      valid: false,
      timeoutError: '제한 설정 정보가 없습니다.',
      maxHopsError: '최대 HOP 정보가 없습니다.',
    };
  }

  let timeoutError: string | null = null;
  if (
    typeof limits.tcp_timeout_ms !== 'number' ||
    !Number.isInteger(limits.tcp_timeout_ms) ||
    limits.tcp_timeout_ms < 100 ||
    limits.tcp_timeout_ms > 60000
  ) {
    timeoutError = 'TCP 타임아웃은 100ms ~ 60,000ms 사이의 정수여야 합니다.';
  }

  let maxHopsError: string | null = null;
  if (
    typeof limits.max_hops !== 'number' ||
    !Number.isInteger(limits.max_hops) ||
    limits.max_hops < 1 ||
    limits.max_hops > 64
  ) {
    maxHopsError = '최대 HOP 수는 1 ~ 64 사이의 정수여야 합니다.';
  }

  return {
    valid: timeoutError === null && maxHopsError === null,
    timeoutError,
    maxHopsError,
  };
}

/**
 * 프로파일을 복제하여 새 프로파일 사본을 생성합니다.
 * 복제 시에도 고위험 캡처 동의(capture_approved)는 안전을 위해 재확인이 필요하므로 false로 초기화합니다.
 */
export function cloneProfile(profile: Profile, customLabel?: string): Profile {
  const cloned = deepClone(profile);
  const safeFeatures = cloned.selected_features.filter((id) => {
    const def = FEATURE_MAP.get(id);
    return def !== undefined && def.cost_class !== 'HIGH';
  });
  return {
    ...cloned,
    profile_id: `${cloned.profile_id}-copy`,
    label: customLabel?.trim() ? customLabel.trim() : `${cloned.label} (복제본)`,
    capture_approved: false,
    selected_features: normalizeFeatureList(safeFeatures),
  };
}

/**
 * 저장되거나 가져온 프로파일(JSON 문자열 또는 객체)을 검증 및 복원합니다.
 * 계약 안전 규칙:
 * - 복원 시 capture_approved를 강제로 false로 해제합니다.
 * - 모든 고비용/위험(HIGH: packet_capture, tcp_traceroute) 기능과 비활성 기능을 선택에서 제거합니다.
 * - 구버전(1.0) 또는 알 수 없는 레거시 기능 ID는 임의 생성하지 않고 무시(ignored_features)하며 경고를 남깁니다.
 */
export function restoreProfile(
  saved: unknown,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): RestoredProfile {
  let parsed: unknown = saved;
  if (typeof saved === 'string') {
    const trimmed = saved.trim();
    if (!trimmed) {
      throw new Error('빈 문자열은 프로파일로 복원할 수 없습니다.');
    }
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error('유효하지 않은 프로파일 JSON 형식입니다.');
    }
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('프로파일 데이터는 JSON 객체여야 합니다.');
  }

  const record = parsed as Record<string, unknown>;
  const defaults = createDefaultProfile();

  const rawSchemaVersion = record.schema_version;
  let legacyMigrated = false;
  if (rawSchemaVersion !== undefined) {
    if (rawSchemaVersion === '1.0') {
      legacyMigrated = true;
    } else if (rawSchemaVersion !== '1.1') {
      throw new Error(`지원하지 않는 프로파일 schema_version입니다: ${String(rawSchemaVersion)}`);
    }
  }

  let mode: DiagnosticMode = defaults.mode;
  if (record.mode !== undefined) {
    if (typeof record.mode !== 'string' || !KNOWN_MODES.has(record.mode as DiagnosticMode)) {
      throw new Error(`지원하지 않는 진단 모드입니다: ${String(record.mode)}`);
    }
    mode = record.mode as DiagnosticMode;
  }

  if (record.selected_features !== undefined && !Array.isArray(record.selected_features)) {
    throw new Error('selected_features 필드는 배열이어야 합니다.');
  }

  const rawFeatures: unknown[] = Array.isArray(record.selected_features)
    ? record.selected_features
    : defaults.selected_features;

  let target: Target = defaults.target;
  if (record.target !== undefined) {
    if (record.target === null || typeof record.target !== 'object' || Array.isArray(record.target)) {
      throw new Error('target 필드는 객체여야 합니다.');
    }
    const rawTarget = record.target as Record<string, unknown>;
    const candidateTarget: Target = {
      host: typeof rawTarget.host === 'string' ? rawTarget.host.trim() : '',
      port: typeof rawTarget.port === 'number' ? rawTarget.port : Number.NaN,
      protocol: 'TCP',
    };
    if (rawTarget.protocol !== undefined && rawTarget.protocol !== 'TCP') {
      throw new Error('target.protocol은 TCP만 지원됩니다.');
    }
    const targetValidation = validateTarget(candidateTarget);
    if (!targetValidation.valid) {
      throw new Error(
        targetValidation.hostError ?? targetValidation.portError ?? '유효하지 않은 target 설정입니다.',
      );
    }
    target = candidateTarget;
  }

  let limits: Limits = defaults.limits;
  if (record.limits !== undefined) {
    if (record.limits === null || typeof record.limits !== 'object' || Array.isArray(record.limits)) {
      throw new Error('limits 필드는 객체여야 합니다.');
    }
    const rawLimits = record.limits as Record<string, unknown>;
    const candidateLimits: Limits = {
      tcp_timeout_ms:
        typeof rawLimits.tcp_timeout_ms === 'number'
          ? rawLimits.tcp_timeout_ms
          : defaults.limits.tcp_timeout_ms,
      max_hops:
        typeof rawLimits.max_hops === 'number' ? rawLimits.max_hops : defaults.limits.max_hops,
      retries:
        typeof rawLimits.retries === 'number' ? rawLimits.retries : defaults.limits.retries,
      max_concurrent_tcp:
        typeof rawLimits.max_concurrent_tcp === 'number'
          ? rawLimits.max_concurrent_tcp
          : defaults.limits.max_concurrent_tcp,
      capture_duration_secs:
        typeof rawLimits.capture_duration_secs === 'number'
          ? rawLimits.capture_duration_secs
          : defaults.limits.capture_duration_secs,
      capture_max_bytes:
        typeof rawLimits.capture_max_bytes === 'number'
          ? rawLimits.capture_max_bytes
          : defaults.limits.capture_max_bytes,
      log_retention_days:
        typeof rawLimits.log_retention_days === 'number'
          ? rawLimits.log_retention_days
          : defaults.limits.log_retention_days,
      ui_updates_per_second:
        typeof rawLimits.ui_updates_per_second === 'number'
          ? rawLimits.ui_updates_per_second
          : defaults.limits.ui_updates_per_second,
    };
    const limitsValidation = validateLimits(candidateLimits);
    if (!limitsValidation.valid) {
      throw new Error(
        limitsValidation.timeoutError ??
          limitsValidation.maxHopsError ??
          '유효하지 않은 limits 설정입니다.',
      );
    }
    limits = candidateLimits;
  }

  const ignoredFeatures: string[] = [];
  const strippedHighCostFeatures: FeatureId[] = [];
  const restoreWarnings: string[] = [];
  const acceptedFeatures: FeatureId[] = [];

  if (record.capture_approved === true) {
    restoreWarnings.push(
      '저장된 프로파일의 패킷 캡처 동의(capture_approved)는 안전 정책에 따라 해제되었습니다. 필요 시 수동으로 다시 동의하십시오.',
    );
  }

  const baseCheckProfile: Pick<Profile, 'capture_approved' | 'mode'> = {
    capture_approved: false,
    mode,
  };

  for (const item of rawFeatures) {
    if (typeof item !== 'string' || !isKnownFeatureId(item)) {
      const unknownStr = String(item);
      if (!ignoredFeatures.includes(unknownStr)) {
        ignoredFeatures.push(unknownStr);
      }
      continue;
    }

    const def = FEATURE_MAP.get(item)!;
    if (def.cost_class === 'HIGH' || isFeatureDisabled(item, baseCheckProfile, capabilities)) {
      if (!strippedHighCostFeatures.includes(item)) {
        strippedHighCostFeatures.push(item);
      }
      continue;
    }

    acceptedFeatures.push(item);
  }

  if (strippedHighCostFeatures.length > 0) {
    restoreWarnings.push(
      `고비용/위험 또는 미지원 기능(${strippedHighCostFeatures.join(', ')})은 복원 시 자동 활성화되지 않고 제외되었습니다.`,
    );
  }

  if (ignoredFeatures.length > 0) {
    restoreWarnings.push(
      `지원되지 않거나 알 수 없는 레거시 기능 ID(${ignoredFeatures.join(', ')})를 무시했습니다.`,
    );
  }

  if (legacyMigrated) {
    restoreWarnings.push('구버전(schema_version 1.0) 프로파일을 1.1 형식으로 안전 변환했습니다.');
  }

  const profileId =
    typeof record.profile_id === 'string' && record.profile_id.trim().length > 0
      ? record.profile_id.trim()
      : 'restored-profile';

  const label =
    typeof record.label === 'string' && record.label.trim().length > 0
      ? record.label.trim()
      : '복원된 프로파일';

  return {
    schema_version: '1.1',
    profile_id: profileId,
    label,
    mode,
    selected_features: normalizeFeatureList(acceptedFeatures),
    capture_approved: false,
    target: deepClone(target),
    limits: deepClone(limits),
    ignored_features: ignoredFeatures,
    stripped_high_cost_features: strippedHighCostFeatures,
    restore_warnings: restoreWarnings,
    legacy_migrated: legacyMigrated,
    legacy_raw_input: legacyMigrated ? deepFreeze(deepClone(record)) : null,
  };
}

export interface ProfileRestoreOutcome {
  readonly ok: boolean;
  readonly profile: RestoredProfile | null;
  readonly error: string | null;
}

/**
 * 예외를 던지지 않고 프로파일 복원 결과를 반환하는 헬퍼입니다.
 */
export function validateAndRestoreProfile(
  raw: unknown,
  capabilities: RuntimeCapabilityState = DEFAULT_G1_CAPABILITIES,
): ProfileRestoreOutcome {
  try {
    const profile = restoreProfile(raw, capabilities);
    return { ok: true, profile, error: null };
  } catch (err) {
    return {
      ok: false,
      profile: null,
      error: err instanceof Error ? err.message : '프로파일 복원 중 알 수 없는 오류가 발생했습니다.',
    };
  }
}

/**
 * 실행 중 프로파일 스냅샷 고정 및 다음 세션 대기열(queued_next_profile) 상태 관리
 * PRD 14.3: 기능 선택 변경은 실행 전에는 즉시 반영, 실행 중에는 다음 세션에만 반영(현재 세션 구성 스냅샷 고정).
 */
export function createExecutionSelectionState(
  initialProfile: Profile = createDefaultProfile(),
): ExecutionSelectionState {
  return {
    is_running: false,
    current_session_profile: null,
    active_profile: deepClone(initialProfile),
    queued_next_profile: null,
  };
}

/**
 * 세션 시작(또는 스냅샷 고정 시뮬레이션) 시 현재 프로파일을 동결(deepFreeze)하여 고정합니다.
 */
export function lockSessionProfileSnapshot(
  state: ExecutionSelectionState,
): ExecutionSelectionState {
  const frozenSnapshot = deepFreeze(deepClone(state.active_profile));
  return {
    is_running: true,
    current_session_profile: frozenSnapshot,
    active_profile: deepClone(state.active_profile),
    queued_next_profile: null,
  };
}

/**
 * 프로파일 편집을 적용합니다.
 * - 비실행(is_running === false): active_profile에 즉시 반영
 * - 실행 중(is_running === true): current_session_profile은 절대 변경하지 않고 queued_next_profile에만 저장
 */
export function applyProfileChangeDuringSession(
  state: ExecutionSelectionState,
  updatedProfile: Profile,
): ExecutionSelectionState {
  const nextCopy = deepClone(updatedProfile);
  if (!state.is_running) {
    return {
      is_running: false,
      current_session_profile: null,
      active_profile: nextCopy,
      queued_next_profile: null,
    };
  }

  return {
    is_running: true,
    current_session_profile: state.current_session_profile,
    active_profile: nextCopy,
    queued_next_profile: deepClone(nextCopy),
  };
}

/**
 * 세션 종료 시 고정된 스냅샷을 해제하고 대기 중이던 다음 프로파일(queued_next_profile)을 활성 프로파일로 승격합니다.
 */
export function releaseSessionProfileSnapshot(
  state: ExecutionSelectionState,
): ExecutionSelectionState {
  const promoted = state.queued_next_profile
    ? deepClone(state.queued_next_profile)
    : deepClone(state.active_profile);
  return {
    is_running: false,
    current_session_profile: null,
    active_profile: promoted,
    queued_next_profile: null,
  };
}

/**
 * 그룹별 결과를 집계합니다.
 * 안전 규칙:
 * - 빈 배열이거나 해당 그룹에 실행 결과가 없으면 summary_status는 'EMPTY'이며 절대 'PASS'로 위장하지 않습니다.
 * - SKIPPED_BY_USER, UNAVAILABLE, ERROR, CANCELLED는 PASS/FAIL로 위장하지 않고 별도 카운트 및 상태로 유지합니다.
 * - 그룹 집계는 개별 기능 결과(items)를 덮어쓰거나 변경하지 않습니다.
 */
export function aggregateGroups(
  featureResults: readonly FeatureResult[],
): GroupAggregation[] {
  return G1_CONTRACT.groups.map((groupId) => {
    const groupMeta = GROUP_LABELS[groupId];
    const definedCount = G1_CONTRACT.features.filter((f) => f.group_id === groupId).length;
    const matchingItems = featureResults
      .filter((r) => r.group_id === groupId && isKnownFeatureId(r.feature_id))
      .map((r) => deepClone(r));

    const counts: Record<FeatureStatus, number> = {
      PASS: 0,
      FAIL: 0,
      WARN: 0,
      SKIPPED_BY_USER: 0,
      UNAVAILABLE: 0,
      ERROR: 0,
      CANCELLED: 0,
    };

    for (const item of matchingItems) {
      if (KNOWN_STATUSES.has(item.status)) {
        counts[item.status] += 1;
      }
    }

    let summaryStatus: GroupSummaryStatus = 'EMPTY';
    const hasExecuted =
      counts.PASS > 0 ||
      counts.FAIL > 0 ||
      counts.WARN > 0 ||
      counts.ERROR > 0 ||
      counts.CANCELLED > 0;

    if (matchingItems.length === 0) {
      summaryStatus = 'EMPTY';
    } else if (counts.FAIL > 0) {
      summaryStatus = 'FAIL';
    } else if (counts.ERROR > 0) {
      summaryStatus = 'ERROR';
    } else if (counts.WARN > 0) {
      summaryStatus = 'WARN';
    } else if (counts.CANCELLED > 0) {
      summaryStatus = 'CANCELLED';
    } else if (counts.PASS > 0) {
      summaryStatus = 'PASS';
    } else if (counts.UNAVAILABLE > 0) {
      summaryStatus = 'UNAVAILABLE';
    } else {
      summaryStatus = 'SKIPPED_BY_USER';
    }

    return {
      group_id: groupId,
      label: groupMeta.name,
      description: groupMeta.summary,
      total_defined_features: definedCount,
      result_count: matchingItems.length,
      has_executed: hasExecuted,
      summary_status: summaryStatus,
      counts: deepFreeze(counts),
      items: matchingItems,
    };
  });
}

/**
 * 세션 객체 내의 feature_results에 세션 메타데이터(session_id, mode, host_role, target)를 결합하여
 * 다차원 결과 필터링이 가능하도록 평탄화합니다.
 */
export function flattenSessionResults(session: Session): FilterableFeatureResult[] {
  return session.feature_results.map((item) => ({
    ...deepClone(item),
    session_id: session.session_id,
    mode: session.mode,
    host_role: session.host_role,
    target: deepClone(session.profile.target),
  }));
}

/**
 * 호스트 역할(client/server/null)의 한국어 표시 라벨을 반환합니다.
 * null 또는 미지정인 경우 '서버'로 오분류하지 않고 '미확인'을 반환합니다.
 */
export function formatHostRoleLabel(role: HostRole | null | undefined): string {
  if (role === 'client') {
    return '클라이언트';
  }
  if (role === 'server') {
    return '서버';
  }
  return '미확인';
}

function formatTargetText(target: Target | string | undefined): string {
  if (!target) {
    return '';
  }
  if (typeof target === 'string') {
    return target;
  }
  return `${target.host}:${target.port}`;
}

const STATUS_SORT_ORDER: Readonly<Record<FeatureStatus, number>> = {
  FAIL: 1,
  ERROR: 2,
  WARN: 3,
  CANCELLED: 4,
  UNAVAILABLE: 5,
  SKIPPED_BY_USER: 6,
  PASS: 7,
};

const CLASSIFICATION_SORT_ORDER: Readonly<Record<EvidenceClassification, number>> = {
  OBSERVED: 1,
  INFERRED: 2,
  UNKNOWN: 3,
};

/**
 * 진단 결과 목록을 그룹/기능/상태/호스트역할/모드/세션/날짜/대상/근거수준/검색어 조건으로 필터링하고 정렬합니다.
 * 원본 배열이나 요소를 변이시키지 않고 깊은 복사본 배열을 반환합니다.
 */
export function filterResults<T extends FilterableFeatureResult>(
  results: readonly T[],
  filters: ResultFilters = {},
): T[] {
  const groupFilter = filters.group_id ?? filters.group ?? '';
  const featureFilter = filters.feature_id ?? filters.feature ?? '';
  const statusFilter = filters.status ?? '';
  const hostRoleFilter = filters.host_role ?? filters.hostRole ?? '';
  const modeFilter = filters.mode ?? '';
  const sessionFilter = (filters.session_id ?? filters.session ?? '').trim().toLowerCase();
  const dateExact = (filters.date ?? '').trim();
  const dateFrom = (filters.date_from ?? filters.dateFrom ?? '').trim();
  const dateTo = (filters.date_to ?? filters.dateTo ?? '').trim();
  const targetFilter = (filters.target ?? '').trim().toLowerCase();
  const classificationFilter =
    filters.classification ?? filters.evidence_level ?? filters.evidenceLevel ?? '';
  const searchQuery = (filters.search ?? filters.query ?? '').trim().toLowerCase();
  const sortByRaw = filters.sort_by ?? filters.sortBy ?? 'default';
  const sortOrder: SortDirection = (filters.sort_order ?? filters.sortOrder ?? 'asc') === 'desc' ? 'desc' : 'asc';

  const filtered = results.filter((item) => {
    if (groupFilter && groupFilter !== 'ALL' && item.group_id !== groupFilter) {
      return false;
    }

    if (featureFilter && featureFilter !== 'ALL' && item.feature_id !== featureFilter) {
      return false;
    }

    if (statusFilter && statusFilter !== 'ALL' && item.status !== statusFilter) {
      return false;
    }

    if (hostRoleFilter && hostRoleFilter !== 'ALL') {
      if ((item.host_role ?? '') !== hostRoleFilter) {
        return false;
      }
    }

    if (modeFilter && modeFilter !== 'ALL') {
      if ((item.mode ?? '') !== modeFilter) {
        return false;
      }
    }

    if (sessionFilter && sessionFilter !== 'all') {
      const itemSession = (item.session_id ?? '').toLowerCase();
      if (!itemSession.includes(sessionFilter)) {
        return false;
      }
    }

    if (dateExact || dateFrom || dateTo) {
      const started = item.started_at_utc ?? '';
      if (!started) {
        return false;
      }
      const itemDatePart = started.slice(0, 10);
      if (dateExact && !started.startsWith(dateExact) && itemDatePart !== dateExact) {
        return false;
      }
      if (dateFrom) {
        const fromComparable = dateFrom.length === 10 ? dateFrom : dateFrom.slice(0, 10);
        if (itemDatePart < fromComparable) {
          return false;
        }
      }
      if (dateTo) {
        const toComparable = dateTo.length === 10 ? dateTo : dateTo.slice(0, 10);
        if (itemDatePart > toComparable) {
          return false;
        }
      }
    }

    if (targetFilter) {
      const itemTarget = formatTargetText(item.target).toLowerCase();
      if (!itemTarget.includes(targetFilter)) {
        return false;
      }
    }

    if (classificationFilter && classificationFilter !== 'ALL') {
      const effectiveClassification: EvidenceClassification = item.classification ?? 'UNKNOWN';
      if (effectiveClassification !== classificationFilter) {
        return false;
      }
    }

    if (searchQuery) {
      const def = FEATURE_MAP.get(item.feature_id);
      const groupMeta = GROUP_LABELS[item.group_id];
      const statusMeta = STATUS_METADATA[item.status];
      const searchableParts = [
        item.feature_id,
        def?.label ?? '',
        def?.description ?? '',
        item.group_id,
        groupMeta?.name ?? '',
        item.status,
        statusMeta?.koreanLabel ?? '',
        item.classification ?? 'UNKNOWN',
        item.error_code !== null ? String(item.error_code) : '',
        item.session_id ?? '',
        item.host_role ?? '',
        formatHostRoleLabel(item.host_role),
        item.mode ?? '',
        formatTargetText(item.target),
        ...item.evidence_ids,
        ...item.limitations,
        ...item.next_checks,
      ]
        .join(' ')
        .toLowerCase();

      if (!searchableParts.includes(searchQuery)) {
        return false;
      }
    }

    return true;
  });

  const clonedResults = filtered.map((item) => deepClone(item));

  const featureOrderMap = new Map<FeatureId, number>(
    G1_CONTRACT.features.map((f, idx) => [f.feature_id, idx]),
  );
  const groupOrderMap = new Map<GroupId, number>(
    G1_CONTRACT.groups.map((g, idx) => [g, idx]),
  );

  clonedResults.sort((a, b) => {
    let cmp = 0;
    switch (sortByRaw) {
      case 'group': {
        cmp = (groupOrderMap.get(a.group_id) ?? 99) - (groupOrderMap.get(b.group_id) ?? 99);
        if (cmp === 0) {
          cmp = (featureOrderMap.get(a.feature_id) ?? 99) - (featureOrderMap.get(b.feature_id) ?? 99);
        }
        break;
      }
      case 'feature': {
        const labelA = FEATURE_MAP.get(a.feature_id)?.label ?? a.feature_id;
        const labelB = FEATURE_MAP.get(b.feature_id)?.label ?? b.feature_id;
        cmp = labelA.localeCompare(labelB, 'ko');
        break;
      }
      case 'status': {
        cmp = (STATUS_SORT_ORDER[a.status] ?? 99) - (STATUS_SORT_ORDER[b.status] ?? 99);
        break;
      }
      case 'duration':
      case 'duration_ms': {
        const durA = a.duration_ms ?? -1;
        const durB = b.duration_ms ?? -1;
        cmp = durA - durB;
        break;
      }
      case 'date':
      case 'time':
      case 'started_at_utc': {
        const timeA = a.started_at_utc ?? '';
        const timeB = b.started_at_utc ?? '';
        cmp = timeA.localeCompare(timeB);
        break;
      }
      case 'evidence_level':
      case 'classification': {
        const classA: EvidenceClassification = a.classification ?? 'UNKNOWN';
        const classB: EvidenceClassification = b.classification ?? 'UNKNOWN';
        cmp =
          (CLASSIFICATION_SORT_ORDER[classA] ?? 99) -
          (CLASSIFICATION_SORT_ORDER[classB] ?? 99);
        break;
      }
      default: {
        cmp = (featureOrderMap.get(a.feature_id) ?? 99) - (featureOrderMap.get(b.feature_id) ?? 99);
        break;
      }
    }

    return sortOrder === 'desc' ? -cmp : cmp;
  });

  return clonedResults;
}

/**
 * 구버전(schema_version=1.0) 세션 데이터를 1.1 형식으로 호환 변환합니다.
 * 계약 안전 규칙:
 * - 원본 입력(raw_legacy_input)을 별도로 동결 보존합니다.
 * - 누락된 필드는 UNKNOWN 또는 null로 유지하며, 가짜 PASS/증거/카운터를 절대 생성하지 않습니다.
 */
export function migrateLegacySession(raw: unknown): Session {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('유효하지 않은 세션 데이터입니다.');
  }
  const rec = raw as Record<string, unknown>;
  const frozenRaw = deepFreeze(deepClone(rec));
  const defaultProfile = createDefaultProfile();

  const sessionId =
    typeof rec.session_id === 'string' && rec.session_id.trim()
      ? rec.session_id.trim()
      : 'legacy-session-unknown';

  const mode: DiagnosticMode =
    rec.mode === 'paired_offline' ? 'paired_offline' : 'standalone';

  const hostRole: HostRole | null =
    rec.host_role === 'client' || rec.host_role === 'server' ? rec.host_role : null;

  const startedAt =
    typeof rec.started_at_utc === 'string' && rec.started_at_utc.trim()
      ? rec.started_at_utc.trim()
      : '1970-01-01T00:00:00Z';

  const timezoneOffsetMinutes: number | null =
    typeof rec.timezone_offset_minutes === 'number' &&
    Number.isFinite(rec.timezone_offset_minutes)
      ? rec.timezone_offset_minutes
      : null;

  return {
    schema_version: '1.1',
    session_id: sessionId,
    mode,
    host_role: hostRole,
    started_at_utc: startedAt,
    timezone_offset_minutes: timezoneOffsetMinutes,
    clock_offset_ms: null,
    clock_uncertainty_ms: null,
    profile: defaultProfile,
    evidence: [],
    feature_results: [],
    findings: [
      {
        classification: 'UNKNOWN',
        statement: '구버전(1.0) 세션 데이터에서 변환됨 — 누락된 판정 및 근거 필드는 UNKNOWN/null로 보존됨',
        evidence_ids: [],
        confidence: 'low',
        limitations: ['구버전 1.0 포맷으로 기능별 상세 측정 스키마가 없음'],
        next_checks: ['1.1 스키마 기반 재진단 또는 원본 로그 확인'],
      },
    ],
    limitations: ['schema_version 1.0 호환 변환 세션 (원본 데이터 raw_legacy_input 별도 보관)'],
    resource_metrics: {
      peak_rss_bytes: null,
      avg_cpu_percent: null,
      capture_drops: null,
    },
    raw_legacy_input: frozenRaw,
  };
}
