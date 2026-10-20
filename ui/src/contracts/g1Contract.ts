import rawContract from '../../../contracts/g1-interface-contract.json';

/**
 * 객체를 재귀적으로 동결(deep freeze)하여 런타임 변조를 방지합니다.
 */
export function deepFreeze<T>(target: T): Readonly<T> {
  if (target === null || typeof target !== 'object') {
    return target;
  }
  Object.freeze(target);
  if (Array.isArray(target)) {
    for (const item of target) {
      deepFreeze(item);
    }
  } else {
    for (const key of Object.keys(target as Record<string, unknown>)) {
      const value = (target as Record<string, unknown>)[key];
      if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        deepFreeze(value);
      }
    }
  }
  return target;
}

export type GroupId =
  | 'G-NET'
  | 'G-PATH'
  | 'G-PKT'
  | 'G-PAIR'
  | 'G-OPS'
  | 'G-EVID';

export type FeatureId =
  | 'tcp_connect'
  | 'icmp_ping'
  | 'dns_lookup'
  | 'icmp_traceroute'
  | 'tcp_traceroute'
  | 'route_table'
  | 'nic_inventory'
  | 'packet_capture'
  | 'syn_rst_analysis'
  | 'firewall_log'
  | 'listening_check'
  | 'agent_session'
  | 'import_bundle'
  | 'packet_compare'
  | 'clock_skew'
  | 'tcp_monitor'
  | 'config_change'
  | 'history_query'
  | 'result_json'
  | 'pdf_report'
  | 'pcap_export'
  | 'hash_verify'
  | 'policy_check';

export type ContractPresetId =
  | 'quick-default'
  | 'path-default'
  | 'precise-default'
  | 'paired-default';

export type PresetSelectionId = ContractPresetId | 'custom';

export type DiagnosticMode = 'standalone' | 'paired_offline';

export type FeatureStatus =
  | 'PASS'
  | 'FAIL'
  | 'WARN'
  | 'SKIPPED_BY_USER'
  | 'UNAVAILABLE'
  | 'ERROR'
  | 'CANCELLED';

export type EvidenceClassification = 'OBSERVED' | 'INFERRED' | 'UNKNOWN';

export type ConfidenceLevel = 'low' | 'medium' | 'high';

export type TcpOutcome =
  | 'CONNECTED'
  | 'REFUSED'
  | 'TIMED_OUT'
  | 'UNREACHABLE'
  | 'LOCAL_ERROR'
  | 'DNS_ERROR'
  | 'CANCELLED';

export type EvidenceKind =
  | 'SOCKET'
  | 'ICMP'
  | 'DNS'
  | 'HOST_SNAPSHOT'
  | 'PACKET'
  | 'CAPTURE_METADATA'
  | 'POLICY_MEMO'
  | 'IMPORT';

export type CostClass = 'LOW' | 'MEDIUM' | 'HIGH';

export type PermissionLevel = 'USER' | 'CONDITIONAL';

export type HostRole = 'client' | 'server';

export interface ContractFeatureDefinition {
  readonly feature_id: FeatureId;
  readonly group_id: GroupId;
  readonly label: string;
  readonly description: string;
  readonly default_selected: boolean;
  readonly requirements: readonly string[];
  readonly dependencies: readonly FeatureId[];
  readonly cost_class: CostClass;
  readonly permission_level: PermissionLevel;
  readonly supported_modes: readonly DiagnosticMode[];
}

export interface G1InterfaceContract {
  readonly contract_version: string;
  readonly prd_sha256: string;
  readonly schema_version: string;
  readonly groups: readonly GroupId[];
  readonly features: readonly ContractFeatureDefinition[];
  readonly presets: Readonly<Record<ContractPresetId, readonly FeatureId[]>>;
  readonly modes: readonly DiagnosticMode[];
  readonly statuses: readonly FeatureStatus[];
  readonly classifications: readonly EvidenceClassification[];
  readonly confidence: readonly ConfidenceLevel[];
  readonly tcp_outcomes: readonly TcpOutcome[];
  readonly tcp_error_mapping: Readonly<Record<string, TcpOutcome>>;
  readonly evidence_kinds: readonly EvidenceKind[];
  readonly safety_rules: readonly string[];
}

/**
 * 중앙 계약 JSON을 복제 없이 직접 임포트하여 동결한 단일 진실 공급원(SSOT)
 */
export const G1_CONTRACT: G1InterfaceContract = deepFreeze(
  rawContract as unknown as G1InterfaceContract,
);

export const GROUP_LABELS: Readonly<Record<GroupId, { readonly name: string; readonly summary: string }>> =
  deepFreeze({
    'G-NET': {
      name: '기본 연결',
      summary: 'TCP 핸드셰이크, ICMP 응답, DNS 이름 풀이 확인',
    },
    'G-PATH': {
      name: '경로·라우팅',
      summary: '로컬 NIC/게이트웨이, 라우팅 테이블, HOP 경로 추적',
    },
    'G-PKT': {
      name: '패킷·방화벽',
      summary: '선택적 패킷 캡처(별도 동의 필수), SYN/RST 분석, 방화벽·리스닝 점검',
    },
    'G-PAIR': {
      name: '양방향 비교',
      summary: '클라이언트·서버 Agent 세션, 오프라인 결과 ZIP 병합, 패킷·시계 오차 비교',
    },
    'G-OPS': {
      name: '운영·모니터링',
      summary: '반복 TCP 점검, 네트워크 구성 변경 감지, 로컬 진단 이력 조회',
    },
    'G-EVID': {
      name: '증빙·보고',
      summary: '기계 판독 결과 JSON, PDF 보고서, PCAP 내보내기, SHA-256 해시 및 정책 검증',
    },
  });

export interface PresetDisplayMeta {
  readonly id: PresetSelectionId;
  readonly label: string;
  readonly description: string;
}

export const PRESET_DISPLAY_LIST: readonly PresetDisplayMeta[] = deepFreeze([
  {
    id: 'quick-default',
    label: '빠른 진단',
    description: '첫 실행 기본값 (TCP + Ping + NIC/게이트웨이 + 라우팅 + 결과 JSON, 5개 기능)',
  },
  {
    id: 'path-default',
    label: '경로 진단',
    description: '빠른 진단 + ICMP 경로 추적 (TCP 경로 추적은 백엔드 검증 전 비활성 제외)',
  },
  {
    id: 'precise-default',
    label: '정밀 증빙',
    description: '경로 진단 + SYN/RST·방화벽·리스닝 점검 (패킷 캡처는 별도 동의 전 자동 활성화 안 됨)',
  },
  {
    id: 'paired-default',
    label: '양방향 비교',
    description: '양측 Agent 세션·오프라인 결과 ZIP 가져오기·패킷 비교·시계 오차 검사 + 결과 JSON',
  },
  {
    id: 'custom',
    label: '사용자 정의',
    description: '그룹/개별 기능을 직접 선택하거나 복원한 프로파일 구성',
  },
]);

export interface StatusBadgeMeta {
  readonly status: FeatureStatus;
  readonly icon: string;
  readonly shortText: string;
  readonly koreanLabel: string;
  readonly description: string;
}

export const STATUS_METADATA: Readonly<Record<FeatureStatus, StatusBadgeMeta>> = deepFreeze({
  PASS: {
    status: 'PASS',
    icon: '✓',
    shortText: 'PASS',
    koreanLabel: '정상 확인',
    description: '측정 및 검증 기준 충족 (서비스/DB 인증 성공을 의미하지 않음)',
  },
  FAIL: {
    status: 'FAIL',
    icon: '✗',
    shortText: 'FAIL',
    koreanLabel: '실패 관찰',
    description: '연결 거부·시간초과·도달 불가 등 실패 현상 관찰 (단독 장비 차단 단정 금지)',
  },
  WARN: {
    status: 'WARN',
    icon: '!',
    shortText: 'WARN',
    koreanLabel: '주의/제한',
    description: '시계 오차·NAT 가능성·일부 비응답 등 해석상 주의 필요',
  },
  SKIPPED_BY_USER: {
    status: 'SKIPPED_BY_USER',
    icon: '—',
    shortText: 'SKIPPED_BY_USER',
    koreanLabel: '사용자 미선택',
    description: '사용자가 프로파일에서 선택하지 않아 실행하지 않음 (PASS/FAIL 아님)',
  },
  UNAVAILABLE: {
    status: 'UNAVAILABLE',
    icon: '⊘',
    shortText: 'UNAVAILABLE',
    koreanLabel: '미지원/의존성 부족',
    description: '권한·드라이버·백엔드 미확보로 실행 불가 (PASS/FAIL 아님)',
  },
  ERROR: {
    status: 'ERROR',
    icon: '⚠',
    shortText: 'ERROR',
    koreanLabel: '로컬/실행 오류',
    description: '로컬 소켓·파서·파일 입출력 등 실행 중 오류 발생 (원격 차단과 분리)',
  },
  CANCELLED: {
    status: 'CANCELLED',
    icon: '⏹',
    shortText: 'CANCELLED',
    koreanLabel: '사용자 중단',
    description: '사용자 취소 또는 시간 제한으로 중단되어 부분 보존됨',
  },
});

/**
 * 기능별 예상 소요시간 추정치(단위: ms).
 * 주의: 실제 측정값이 아니라 UI에서 선택 항목에 따른 대략적인 예상치 안내용 상수입니다.
 */
export const FEATURE_ESTIMATED_DURATION_MS: Readonly<Record<FeatureId, number>> = deepFreeze({
  tcp_connect: 1500,
  icmp_ping: 1200,
  dns_lookup: 400,
  icmp_traceroute: 6000,
  tcp_traceroute: 8000,
  route_table: 300,
  nic_inventory: 300,
  packet_capture: 10000,
  syn_rst_analysis: 800,
  firewall_log: 600,
  listening_check: 400,
  agent_session: 500,
  import_bundle: 700,
  packet_compare: 1200,
  clock_skew: 400,
  tcp_monitor: 2000,
  config_change: 500,
  history_query: 300,
  result_json: 200,
  pdf_report: 1500,
  pcap_export: 600,
  hash_verify: 300,
  policy_check: 400,
});
