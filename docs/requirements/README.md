# 요구사항 원문과 제품별 적용 범위

- `../../PRD.md`: 기존 v1.1 원문. Inspector 기존 G1 계약의 `prd_sha256` 및 역사적 검증 근거이므로 덮어쓰지 않는다.
- `Network_Path_Inspector_Harness_PRD_v1.2.md`: 2026-10-21 사용자가 제공한 최신 원문. Part A는 기존 Inspector 요구사항을 유지하고 Part B는 별도 Network Quick Check 제품을 추가한다.
- 첨부 원문 v1.2 SHA-256: `a999eaff063db5c1ecf11d616eb116735eb692833d33121026a53c06dddaaf6f`. 첨부 파일과 저장 사본의 바이트 일치를 검사했다. `.gitattributes`에서 원문 바이트를 보존한다.

## 승인된 개발 구분
- 같은 프로젝트 경로와 Rust workspace를 사용하되 Quick Check 앱은 `apps/network-quick-check/`로 분리한다.
- `crates/network-core/`가 기존 `npi-core`/`npi-probes` 구현을 공유하는 공통 진입점을 제공한다. 기존 Inspector 소스나 데이터 계약을 대규모 이동·재작성하지 않는다.
- Quick Check는 QG0~QG1부터 별도 검증한다. 기존 Inspector의 미완료 G2 상태와 Quick의 QG 상태를 합산하거나 서로 통과로 간주하지 않는다.
- GUI/단일 EXE/깨끗한 Windows VM 실행은 향후 게이트의 실측 대상이며 현재 구현 완료가 아니다.
- 운영망·방화벽·라우트·드라이버·레지스트리·DB 변경은 이 문서 또는 원문의 예시 주소로 승인되지 않는다.
