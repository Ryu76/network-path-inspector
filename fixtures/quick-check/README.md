# Network Quick Check QG1 테스트 픽스처

본 디렉토리의 모든 파일은 Network Quick Check 결과 계약(`qg1-contract.json` 및 `schemas/quick-check-result-1.0.schema.json`) 검증을 위한 **합성(synthetic) 테스트 픽스처**입니다. 실제 네트워크 호출이나 운영망 조작 없이 DTO 및 JSON Schema의 정합성을 검증하기 위해 생성되었습니다.

## 픽스처 목록

### 양성(Valid) 픽스처
1. `synthetic-valid-tcp-connected.json`: TCP 핸드셰이크 성공(`CONNECTED`) 결과 (상태: `PASS`, 근거 수준: `OBSERVED`).
2. `synthetic-valid-tcp-cancelled-nulls.json`: 취소(`CANCELLED`) 결과이며 미확인 nullable 필드 5건이 모두 `null`인 정규 결과 (상태: `UNKNOWN`, 근거 수준: `UNKNOWN`).

### 음성(Invalid) 픽스처
3. `synthetic-invalid-port-zero.json`: 허용 범위를 벗어난 대상 포트(`target_port = 0`)로 인한 거부 검증용.
4. `synthetic-invalid-status.json`: 계약에 정의되지 않은 잘못된 상태 문자열(`status = "INVALID_STATUS"`) 거부 검증용.
5. `synthetic-invalid-missing-field.json`: 계약 필수 필드(`evidence_level`) 누락 거부 검증용.
6. `synthetic-invalid-unknown-field.json`: 계약 외 정의되지 않은 임의 필드(`prohibited_extra_field`, `additionalProperties: false` 위반) 거부 검증용.
