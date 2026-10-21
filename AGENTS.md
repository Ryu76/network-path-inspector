# NPI 작업 안전 규칙
- PRD.md 원문 보존. 제품은 Network Path Inspector이며 LibMate/SeatMate 등 타 프로젝트를 읽거나 수정하지 않는다.
- 맡은 전용 worktree의 명시된 허용 경로만 FILE READ/EDIT/CREATE. 부모가 명령·시험·의존성 설치·통합 수행. 외부 CLI/에이전트 재위임 금지.
- 운영망·임의 대상·예시192.168.* 주소 접속, 스캔, OS 정책/방화벽/라우트/레지스트리·인증서 저장소 변경, 관리자 상승, Npcap/드라이버/서비스 설치, DB 인증/SQL 금지.
- 네트워크 실제 시험은 부모가 만든 127.0.0.1/::1의 제한된 단일 대상에만 허용. P0 G0/G1 구현에는 실제 프로브가 없다.
- 계정·토큰·비밀번호 읽기/기록 금지. 샌드박스/권한 우회 금지, 필요하면 [PERMISSION_REQUIRED] 반환. git commit/push/merge/배포는 부모만 수행하며 외부 게시 금지.
- 측정/추론/미확인 구분. 캡처 없으면 SYN/RST 패킷 관찰 단정 금지. last hop=차단장비 금지. 성능 예산은 측정 전 목표일 뿐이다.
- 공통 contracts/g1-interface-contract.json 그대로 준수. 임의 모델/필드/상태/기능ID 변경 금지. G2~G8 프로브/캡처/보고/설치 구현은 G0/G1 검증 전 보류.
- 결과 상태 SKIPPED_BY_USER, UNAVAILABLE, ERROR, CANCELLED는 PASS/FAIL로 위장하지 않는다. 실패 기대값을 지우지 않는다.
- 한국어 UI/설명 주석, UTF-8·마지막개행·후행공백 없음. 완료 주장 대신 실제 변경 경로·부모 검증 필요사항 반환.

## QG0/QG1 승인 범위
- 같은 프로젝트의 Part B Network Quick Check를 별도 제품으로 준비한다. 원문 docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md와 .harness/references/qg1-contract.json 준수.
- 기존 Inspector 기능/DTO/프로브/스키마/PRD.md 바이트 변경 금지. Quick Check에 웹뷰/Npcap/Agent/PDF/SQLite 의존성 금지.
