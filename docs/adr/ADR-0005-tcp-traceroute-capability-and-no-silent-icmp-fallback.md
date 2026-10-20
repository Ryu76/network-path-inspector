# ADR-0005: TCP 경로 추적(`tcp_traceroute`) 백엔드 전제조건 검증 및 무언(Silent) ICMP 대체 금지

- 상태: Accepted
- 작성일: 2026-10-20
- 관련 요구사항: PRD 2.1 (P0-04), 4.2, 10.1, 14.3, 15 (G3); `contracts/g1-interface-contract.json`

## 1. 배경 및 문제 (Context)
- `PRD.md` P0-04는 "ICMP 경로 추적 + 가능 시 TCP TTL 프로브; 각 HOP의 응답/비응답과 방법 명시"를 요구한다.
- Windows 환경에서 `icmp_traceroute`는 `Iphlpapi.dll`(`IcmpSendEcho2` + `IP_OPTION_INFORMATION.Ttl`)을 통해 일반 사용자 권한으로 수행할 수 있으나, `tcp_traceroute`(TCP SYN 패킷의 IP TTL을 조절하고 중간 라우터의 ICMP Time Exceeded 및 최종 대상의 SYN-ACK/RST를 매칭하는 작업)는 Windows Raw Socket 제약이나 Npcap 패킷 캡처 드라이버 및 권한에 의존한다.
- `PRD.md` 14.3절은 "TCP Traceroute에 필요한 패킷 캡처·권한은 플랫폼 구현에 따라 검증하고, 불가하면 대체 검사로 전환하거나 미지원으로 기록. 조용히 ICMP 결과를 TCP 결과로 바꾸지 않는다"라고 명시한다.

## 2. 출처 사실 (Source Facts)
- Windows ICMP API 문서(`https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2`, `.harness/references/icmp-api.txt`)에 따르면 `IcmpSendEcho2`는 IPv4 ICMP Echo 요청 전용 API이며 TCP 세그먼트를 전송하지 않는다.
- `contracts/g1-interface-contract.json`에서 `tcp_traceroute` 기능은 다음과 같이 정의되어 있다:
  - `group_id`: `"G-PATH"`
  - `requirements`: `["validated_tcp_ttl_backend"]`
  - `cost_class`: `"HIGH"`
  - `permission_level`: `"CONDITIONAL"`

## 3. 결정 (Decision)
1. **전제조건(`validated_tcp_ttl_backend`) 엄격 검증**:
   - `tcp_traceroute`는 실제 TCP TTL 제어와 중간 HOP ICMP/TCP 응답 상관 분석이 검증된 백엔드(`validated_tcp_ttl_backend`) 및 필요한 권한/캡처 드라이버가 준비된 경우에만 실행한다.
2. **무언(Silent) ICMP 폴백 절대 금지**:
   - `validated_tcp_ttl_backend`가 준비되지 않았거나 권한/드라이버가 부족할 때, 내부적으로 ICMP Echo 기반 추적(`icmp_traceroute`)을 실행한 뒤 그 결과를 `tcp_traceroute`의 `PASS`/`FAIL` 결과로 위장하여 반환하는 행위를 **절대 금지**한다.
   - 백엔드 전제조건 미충족 시 `tcp_traceroute`의 `FeatureResult.status`는 반드시 `UNAVAILABLE`로 기록하고, `limitations[]`에 미지원/권한 부족 사유를 명시하며, 사용자가 원할 경우 별도의 `icmp_traceroute` 기능을 통해 ICMP 기반 경로 추적을 확인하도록 안내(`next_checks[]`)한다.
3. **HOP별 프로브 방법 명시 및 단정 금지**:
   - 경로 추적 결과의 모든 HOP 레코드에는 실제로 사용한 프로브 방식(`ICMP_ECHO` vs `TCP_SYN_TTL`)을 명시한다.
   - 방화벽이 ICMP는 차단하고 TCP만 허용하는 구간(또는 그 반대)을 정확히 구분하며, 중간 미응답 HOP을 차단 장비로 단정하지 않고 `UNKNOWN`으로 기록한다.

## 4. 결과 및 영향 (Consequences)
- ICMP가 차단된 망에서 TCP 경로 추적의 실패/미지원을 ICMP 결과로 덮어써서 진단을 오도하는 위험이 제거된다.
- G1/G3 게이트 검증에서 `validated_tcp_ttl_backend` 미존재 시 `tcp_traceroute`가 정확히 `UNAVAILABLE`을 반환하는지 결정론적으로 테스트할 수 있다.
