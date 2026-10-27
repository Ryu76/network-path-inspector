# Architecture Decision Records (ADR) 목록

본 디렉터리는 Network Path Inspector (NPI) G0 단계에서 식별된 `PRD.md`(v1.1.0) 내 모호성 해결 결과와 G0 안전 개발 경계 및 운영 배포 선행 조건 분리 결정을 기록한다. 모든 결정은 `contracts/g1-interface-contract.json`(`contract_version: "g1-1.1.0"`)을 단일 계약 기준으로 준수하며, 현재 코어/런타임 미구현 및 G1 미통과 상태에서 향후 게이트들이 검증할 **설계 목표(Design Goals) 및 수용 계획**을 정의한다.

## ADR 색인

| ADR ID | 제목 | 상태 | 핵심 결정 요약 |
|---|---|---|---|
| [ADR-0001](./ADR-0001-g0-development-scope-and-os-support.md) | G0 안전 개발 범위, x64 타깃, OS 지원 검증 경계 및 미서명 개발 빌드 정책 | Accepted (G0 Baseline) | 초기 타깃 x64 전용; Win10 Pro 19045는 개발 호스트 환경으로만 확인됨(NPI 런타임 호환성 검증 완료 아님, 코어 비어 있음·G1 미통과); Win11/Server 2016+ 테스트 대기(pending); 서명 전 로컬 미서명 개발 빌드만 허용. |
| [ADR-0002](./ADR-0002-npcap-optional-adapter-and-licensing.md) | Npcap 선택적 외부 설치 어댑터 연동 및 라이선스 승인 분리 | Accepted (G0 Baseline) | 외부 기설치 어댑터 전용(번들·무인 설치(`/S`)·대리 동의·권한 상승·드라이버 변경 금지) 정책 유지; 무료/데모 적용 가능성·예외 확인 없이 전 내부 사용자 OEM 강제 구매를 단정하지 않으며, 사용/번들 전 조직의 적용 라이선스 검토를 G4/G8 선행 조건(`blocked`)으로 분리. |
| [ADR-0003](./ADR-0003-preset-quick-default-and-registry-contract.md) | 빠른 진단(`quick-default`) 프리셋 5개 기능 정규화 및 6그룹/23기능 고정 계약 | Accepted | PRD 14.4절 예시(4개)와 14.1절 표 기본 선택(5개) 간 불일치를 계약(`quick-default` 5개: `tcp_connect`, `icmp_ping`, `nic_inventory`, `route_table`, `result_json`)으로 확정(G1 검증 예정). |
| [ADR-0004](./ADR-0004-selective-execution-shared-collectors-and-profile-restore.md) | 미선택 진단 기능 프로브 0회, 내부 선행 수집기 1회 공유 및 고비용 프로파일 복원 재확인 설계 | Accepted | 미선택 진단 기능은 `SKIPPED_BY_USER`(프로브 0회 설계 목표); 선행 로컬 인벤토리는 내부 1회 공유만 허용하고 캡처 자동 동의 금지; 프로파일 복원 시 `capture_approved` 제거 및 `HIGH` 비용 기능 재확인 설계(G1~G4 검증 예정). |
| [ADR-0005](./ADR-0005-tcp-traceroute-capability-and-no-silent-icmp-fallback.md) | TCP 경로 추적(`tcp_traceroute`) 백엔드 전제조건 검증 및 무언(Silent) ICMP 대체 금지 | Accepted | `tcp_traceroute`는 `validated_tcp_ttl_backend` 및 필요 권한/캡처 충족 시에만 실행하며, 미충족 시 `UNAVAILABLE`로 기록하고 조용히 ICMP Traceroute 결과로 위장·대체하지 않도록 설계(G1/G3 검증 예정). |
| [ADR-0006](./ADR-0006-privacy-masking-offline-pairing-and-evidence-provenance.md) | 보고서 기본 마스킹 ON, 허위 익명성 보장 금지, 오프라인 병합 기본 및 증거 출처 분리 | Accepted | 기본 보고서 마스킹 ON, 원본 로컬 비공개 보관 및 반출 시 명시적 노출 경고(허위 익명성 보장 금지); 오프라인 병합(`paired_offline`) 기본; 원본/정규화 분리, 합성 픽스처 `synthetic: true`, 미확인 시계 오차 `null` 유지 설계(G1/G5/G6 검증 예정). |
