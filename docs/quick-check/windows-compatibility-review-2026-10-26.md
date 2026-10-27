# Windows 배포 목표 호환성 검토 — 2026-10-26

## 목표와 현재 판정
- 사용자 목표: Windows 10/11 및 Windows Server 2012 이후 전체 버전. Server 2012와 2012 R2를 목표에서 제외하지 않는다.
- 현재 개발 기준은 Rust 1.98.0 / x86_64-pc-windows-msvc다. x64 전용 사용자 승인이라고 표현하지 않는다.
- Rust 표준 MSVC target 공식 요구는 Windows 10 / Server 2016 이상이다. 따라서 Server 2012/R2는 별도 legacy 빌드·실행 검토가 필요하다. MSRV와 실행 OS 하한은 서로 다른 항목이다.
- win7-windows-msvc는 Tier 3, 미리 빌드된 std가 배포되지 않는 조사 후보다. 설치·빌드·2012 동작은 아직 확인하지 않았고 전역 toolchain을 변경하지 않았다.

## 실제 수행한 추가 조사
- cargo tree --offline --locked -p network-quick-check --target x86_64-pc-windows-msvc -e normal,build: exit0.
- 일반 제품 그래프에서 Tokio1.52.3 / Mio1.2.0 / socket2 0.6.3 / windows-sys0.61.2 / windows-link0.2.1을 확인했다. dev-only process의 bytes는 이 일반 그래프에 나타나지 않았다.
- 설치돼 있던 MSVC dumpbin.exe로 기존 debug NetworkQuickCheck.exe의 /headers와 /imports를 읽었다. 둘 다 exit0. 새 제품 빌드나 실행을 한 것이 아니다.
- 검사 대상: .harness/targets/qg2i-explicit-tcp-root-shared/debug/NetworkQuickCheck.exe
- SHA256: 7f6d9138513f0f6c0990e621f0ce558221711bc40fb93cb98ece08e363d15638 (기존 qg2i 수용 EXE와 동일).
- 관측: x64 PE32+, Windows CUI subsystem, OS/subsystem header6.00, Resource Directory0, Certificates Directory0, Delay Import Directory0.
- 관측 import: api-ms-win-core-synch-l1-2-0.dll의 WaitOnAddress/WakeByAddressAll/WakeByAddressSingle, bcryptprimitives.dll의 ProcessPrng, VCRUNTIME140.dll 및 여러 api-ms-win-crt-* DLL, kernel32/iphlpapi/ws2_32/ntdll 함수.
- 이 debug EXE는 동적 CRT import가 있으므로 무설치 Release 인증 근거가 아니다. PE header6.00도 낮은 OS에서 실행된다는 증거가 아니다. Resource Directory0만으로 현재 정책/미래 GUI manifest를 인증하지 않는다.
- ProcessPrng가 관측됐지만 이를 Server2012 로딩 실패로 단정하지 않는다. Microsoft 공식 ProcessPrng 페이지는 최소 client Windows8 / 최소 server WindowsServer2008R2로 기재한다. 실제 각 OS의 DLL export, 업데이트 수준, ABI와 실행 증거는 별도 필요하다.

## 지원 검증 목록
- Windows 10, Windows 11: 각각 실제 빌드/패치/아키텍처와 검사 기능 증거를 별도 관리한다.
- Server 2012, 2012 R2: 각각 legacy 호환 빌드·PE·실행 검증 차단 상태, 목표는 유지한다.
- Server 2016, 2019, 2022, 2025 및 기타 해당 릴리스: 버전·설치 형태별 검증 대기. 공식 target 하한 안이라는 이유로 제품 지원을 수용하지 않는다.
- Server Core와 Desktop Experience: GUI 실행 범위와 기존 CLI/진단 코어 실행 범위를 별도로 검토한다. Core 제외를 승인받은 것으로 쓰지 않는다.
- 향후 릴리스는 출시 후 검증 대상으로 남긴다. '전체'를 미래 버전 무조건 실행 보장으로 표현하지 않는다.

## 유지할 경계
- static CRT는 배포 의존성 문제의 일부일 뿐 OS API 하한을 해결하지 않는다.
- 선택 기능을 호출하지 않는 것만으로 정적 import가 제거되거나 낮은 OS에서 로드된다는 주장을 하지 않는다.
- 기존 보호 코어/PRD/표준 toolchain을 호환성 조사 때문에 임의 수정하지 않는다.
- 별도 VM/서버의 주소·접근 방식·허용 범위가 없으므로 운영 장비를 추측해 접속하지 않는다. 로컬 검증은 감독자가 자동 수행한다.
- 이번 결과는 정적 소스/기존 debug 바이너리 조사다. Release 단일 EXE, clean VM, 일반사용자, GUI, 서명, 성능, 전체 지원 인증이 아니다.

## 근거
- 독립 읽기전용 소스 검토: deleg_796f094f/task-1. 본 문서는 부모가 직접 관측한 추가 명령과 구분해 정리한 기록이다.
- artifacts/commands/qg3a-modern-normal-dependency-tree.{json,log}
- artifacts/commands/qg3a-current-debug-pe-imports.{json,log}
- artifacts/commands/qg3a-current-debug-pe-headers.{json,log}
- https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html
- https://doc.rust-lang.org/rustc/platform-support/win7-windows-msvc.html
- https://learn.microsoft.com/en-us/windows/win32/seccng/processprng

공식 문서는 직접 HTTPS로 읽었으며 검색/추출 backend 실패를 지원 검증 성공으로 바꾸지 않았다.
