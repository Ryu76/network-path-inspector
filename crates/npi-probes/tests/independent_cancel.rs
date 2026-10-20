//! 감독자 독립 시험: 진행 중 취소·후속 프로브 억제·실제 프로세스 핸들 수 복원.
//! 기본 시험에서는 실행하지 않고 부모가 루프백 허용 후 --ignored로 명시 실행한다.

#[cfg(windows)]
mod windows_only {
    use npi_probes::engine::run_profile;
    use serde_json::{Value, json};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    fn handles() -> u32 {
        let mut count = 0;
        // SAFETY: 현재 프로세스 의사 핸들과 유효한 u32 출력 포인터만 읽기 전용으로 전달한다.
        let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
        assert_ne!(ok, 0, "현재 시험 프로세스 핸들 수 조회 실패");
        count
    }

    async fn cancelled_attempt(port: u16) -> Value {
        let mut profile: Value = serde_json::from_str(include_str!(
            "../../../fixtures/g1/valid_profile_quick.json"
        ))
        .expect("고정 프로필 fixture 구문");
        profile["target"] = json!({"host":"127.0.0.1", "port":port, "protocol":"TCP"});
        profile["selected_features"] =
            json!(["tcp_connect", "icmp_ping", "nic_inventory", "route_table"]);
        profile["limits"]["tcp_timeout_ms"] = json!(5000);
        profile["limits"]["retries"] = json!(0);
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancel);
        // 현재 스레드 Tokio 실행기 밖에서 실제 진행 중 취소를 전달한다.
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            signal.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let output = run_profile(&profile, cancel).await.expect("취소 결과 반환");
        sender.join().expect("취소 전달 스레드 정리");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "PRD 취소 후 정리 목표 3초 초과"
        );
        assert_eq!(
            output["collector_counts"],
            json!({"tcp_connect":1,"icmp_ping":0,"host_network_snapshot":0})
        );
        let rows = output["feature_results"]
            .as_array()
            .expect("기능 결과 배열");
        for id in ["tcp_connect", "icmp_ping", "nic_inventory", "route_table"] {
            let row = rows
                .iter()
                .find(|x| x["feature_id"] == id)
                .expect("선택 기능 결과");
            assert_eq!(row["status"], "CANCELLED", "{id}의 취소 상태");
            assert_eq!(row["evidence_ids"], json!([]));
            if id != "tcp_connect" {
                assert!(row["duration_ms"].is_null(), "미실행 기능 시간 위조 금지");
            }
        }
        assert_eq!(
            output["measurements"]["tcp_connect"]["outcome"],
            "CANCELLED"
        );
        assert_eq!(
            output["measurements"]
                .as_object()
                .expect("원시 결과 객체")
                .len(),
            1
        );
        output
    }

    #[tokio::test]
    #[ignore = "진행 중 취소 및 프로세스 핸들 실측: 부모 명시 실행"]
    async fn in_flight_cancel_stops_later_collectors_and_returns_handles_to_baseline() {
        // 부모가 보유한 단일 루프백 포트를 bind만 하고 listen하지 않는다. 포트 재사용 경합 없음.
        let reserved = tokio::net::TcpSocket::new_v4().expect("시험 소켓 생성");
        reserved
            .bind("127.0.0.1:0".parse().expect("루프백 주소"))
            .expect("시험 전용 포트 예약");
        let port = reserved.local_addr().expect("예약 포트").port();
        cancelled_attempt(port).await; // Tokio 및 Winsock 초기 자원은 기준 측정 전에 준비한다.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = handles();
        for _ in 0..10 {
            cancelled_attempt(port).await;
            // 단일 대상·순차 실행·간격 유지. 부하 시험이나 포트 스캔이 아니다.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let after = handles();
        assert_eq!(
            after, before,
            "취소 반복 후 시험 프로세스 핸들 수가 기준으로 복원되지 않음"
        );
        println!("independent_cancel_attempts=11 handles_before={before} handles_after={after}");
    }
}
