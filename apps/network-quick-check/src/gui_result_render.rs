//! 순수 최종 결과 화면 변환. 화면 상한은 원본 보고서의 보관/누락 정책과 별개다.
//! 스레드·시계·runtime·네트워크·Win32·파일/clipboard 호출 없이 기존 ResultView를 소비한다.
//! 상한 소진은 즉시 오류로 전파해 JSON 직렬화와 후속 순회를 중단한다.
use crate::gui_state::{RunPhase, RunSnapshot};
use crate::result_view::{ResultView, evidence_display, feature_display_ko, status_display};
use network_core::quick::QuickResult;
use network_core::runner::{QuickRunReport, QuickRunRequest};
use network_core::targets::{QuickOptions, QuickPlan, QuickTarget};
use std::io::{self, Write};

pub const TRUNCATION_MARKER: &str =
    "\n... [화면 표시 용량 초과로 일부 내용이 생략되었습니다] ...\n";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedResult {
    pub text: String,
    pub truncated: bool,
    pub displayed_rows: usize,
}

// 이 메모리 writer는 io trait만 구현한다. 실제 파일 I/O도, 두 write_fmt 후보 충돌도 없다.
struct BoundedWriter {
    buffer: Vec<u8>,
    max_bytes: usize,
    body_limit: usize,
    truncated: bool,
}
impl BoundedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_bytes,
            body_limit: max_bytes.saturating_sub(TRUNCATION_MARKER.len()),
            truncated: false,
        }
    }
    fn finish(mut self) -> (String, bool) {
        if self.truncated {
            // 바이트 경계에서 끊긴 마지막 UTF-8 문자만 화면에서 제거한다. 원문은 수정하지 않는다.
            if let Err(e) = std::str::from_utf8(&self.buffer) {
                self.buffer.truncate(e.valid_up_to());
            }
            if self.max_bytes < TRUNCATION_MARKER.len() {
                self.buffer.clear();
                let mut end = self.max_bytes;
                while !TRUNCATION_MARKER.is_char_boundary(end) {
                    end -= 1;
                }
                self.buffer
                    .extend_from_slice(&TRUNCATION_MARKER.as_bytes()[..end]);
            } else {
                self.buffer.extend_from_slice(TRUNCATION_MARKER.as_bytes());
            }
        }
        (
            String::from_utf8(self.buffer).expect("정적 문구와 JSON UTF-8만 기록"),
            self.truncated,
        )
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.truncated {
            return Err(io::Error::other("화면 상한 소진"));
        }
        let remaining = self.body_limit.saturating_sub(self.buffer.len());
        if buf.len() > remaining {
            self.buffer.extend_from_slice(&buf[..remaining]);
            self.truncated = true;
            return Err(io::Error::other("화면 상한 소진"));
        }
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// 직접 의존하는 serde_json만 사용한다. Core의 비-Serialize 계획 타입과 manifest는 변경하지 않는다.
macro_rules! stream_json {
    ($writer:expr,$value:expr) => {
        serde_json::to_writer(&mut *$writer, $value).map_err(io::Error::other)
    };
}
macro_rules! json_field {
    ($writer:expr,$label:expr,$value:expr $(,)?) => {{
        let output = &mut *$writer;
        (|| -> io::Result<()> {
            write!(output, "{}: ", $label)?;
            stream_json!(output, $value)?;
            writeln!(output)
        })()
    }};
}
fn write_target(w: &mut BoundedWriter, t: &QuickTarget) -> io::Result<()> {
    w.write_all(b"{\"host\":")?;
    stream_json!(w, &t.host)?;
    w.write_all(b",\"port\":")?;
    stream_json!(w, &t.port)?;
    w.write_all(b",\"raw_input\":")?;
    stream_json!(w, &t.raw_input)?;
    w.write_all(b"}")
}
fn write_targets<'a>(
    w: &mut BoundedWriter,
    targets: impl IntoIterator<Item = &'a QuickTarget>,
) -> io::Result<()> {
    w.write_all(b"[")?;
    for (index, t) in targets.into_iter().enumerate() {
        if index > 0 {
            w.write_all(b",")?;
        }
        write_target(w, t)?;
    }
    w.write_all(b"]")
}
fn write_options(w: &mut BoundedWriter, o: &QuickOptions) -> io::Result<()> {
    w.write_all(b"{\"tcp_timeout_ms\":")?;
    stream_json!(w, &o.tcp_timeout_ms)?;
    w.write_all(b",\"concurrency\":")?;
    stream_json!(w, &o.concurrency)?;
    w.write_all(b",\"selected_features\":")?;
    stream_json!(w, &o.selected_features)?;
    w.write_all(b"}")
}
fn write_request(w: &mut BoundedWriter, r: &QuickRunRequest) -> io::Result<()> {
    w.write_all(b"{\"session_id\":")?;
    stream_json!(w, &r.session_id)?;
    w.write_all(b",\"timestamp_iso8601\":")?;
    stream_json!(w, &r.timestamp_iso8601)?;
    w.write_all(b",\"source_host\":")?;
    stream_json!(w, &r.source_host)?;
    w.write_all(b",\"targets\":")?;
    write_targets(w, &r.targets)?;
    w.write_all(b",\"options\":")?;
    write_options(w, &r.options)?;
    w.write_all(b",\"max_result_bytes\":")?;
    stream_json!(w, &r.max_result_bytes)?;
    w.write_all(b"}")
}
fn write_plan(w: &mut BoundedWriter, p: &QuickPlan) -> io::Result<()> {
    w.write_all(b"{\"targets\":[")?;
    for (index, t) in p.targets.iter().enumerate() {
        if index > 0 {
            w.write_all(b",")?;
        }
        w.write_all(b"{\"target\":")?;
        write_target(w, &t.target)?;
        w.write_all(b",\"features\":")?;
        stream_json!(w, &t.features)?;
        w.write_all(b",\"requires_resolution\":")?;
        stream_json!(w, &t.requires_resolution)?;
        w.write_all(b"}")?;
    }
    w.write_all(b"],\"tcp_timeout_ms\":")?;
    stream_json!(w, &p.tcp_timeout_ms)?;
    w.write_all(b",\"icmp_timeout_ms\":")?;
    stream_json!(w, &p.icmp_timeout_ms)?;
    w.write_all(b",\"concurrency\":")?;
    stream_json!(w, &p.concurrency)?;
    w.write_all(b",\"limitations\":")?;
    stream_json!(w, &p.limitations)?;
    w.write_all(b"}")
}
fn write_snapshot_raw(w: &mut BoundedWriter, s: &RunSnapshot) -> io::Result<()> {
    w.write_all(b"{\"run_id\":")?;
    stream_json!(w, &s.run_id().as_u64())?;
    w.write_all(b",\"request\":")?;
    write_request(w, s.request())?;
    w.write_all(b",\"plan\":")?;
    write_plan(w, s.plan())?;
    w.write_all(b"}")
}
fn write_report_meta(w: &mut BoundedWriter, r: &QuickRunReport) -> io::Result<()> {
    w.write_all(b"{\"cancelled\":")?;
    stream_json!(w, &r.cancelled)?;
    w.write_all(b",\"limit_reached\":")?;
    stream_json!(w, &r.limit_reached)?;
    w.write_all(b",\"omitted_results\":")?;
    stream_json!(w, &r.omitted_results)?;
    w.write_all(b",\"errors\":")?;
    stream_json!(w, &r.errors)?;
    w.write_all(b",\"invocations\":")?;
    stream_json!(w, &r.invocations)?;
    w.write_all(b",\"max_active_targets\":")?;
    stream_json!(w, &r.max_active_targets)?;
    w.write_all(b",\"targets_started\":")?;
    stream_json!(w, &r.targets_started)?;
    w.write_all(b",\"targets_completed\":")?;
    stream_json!(w, &r.targets_completed)?;
    w.write_all(b",\"serialized_result_bytes\":")?;
    stream_json!(w, &r.serialized_result_bytes)?;
    w.write_all(b"}")
}

pub const fn phase_display_ko(phase: RunPhase) -> &'static str {
    match phase {
        RunPhase::Ready => "진단 준비 완료 (Ready)",
        RunPhase::Running => "진단 진행 중 (Running - 중간 진행률 및 중간 실측 미제공)",
        RunPhase::Cancelling => "취소 처리 중 (Cancelling - 비동기 정리 대기 중)",
        RunPhase::Finished => "진단 완료 (Finished)",
    }
}
fn render_snapshot(w: &mut BoundedWriter, snapshot: Option<&RunSnapshot>) -> io::Result<()> {
    writeln!(w, "=== 제공된 완료 자료의 실행 스냅샷 정보 ===")?;
    writeln!(
        w,
        "보고서와 snapshot의 동일 실행 귀속은 caller 책임이며 이 화면 변환은 검증하지 않습니다."
    )?;
    if let Some(snap) = snapshot {
        writeln!(w, "실행 식별자 (RunId): {}", snap.run_id())?;
        json_field!(w, "세션 ID", &snap.request().session_id)?;
        json_field!(
            w,
            "요청 일시 (null은 미확인)",
            &snap.request().timestamp_iso8601,
        )?;
        json_field!(
            w,
            "출발지 호스트 (null은 미확인)",
            &snap.request().source_host
        )?;
        writeln!(w, "요청 대상 수: {}개", snap.request().targets.len())?;
        writeln!(
            w,
            "TCP 타임아웃: {} ms",
            snap.request().options.tcp_timeout_ms
        )?;
        writeln!(w, "진단 계획 (QuickPlan):")?;
        writeln!(w, "계획된 대상 수: {}개", snap.plan().targets.len())?;
        write!(w, "snapshot_raw=")?;
        write_snapshot_raw(w, snap)?;
        writeln!(w)?;
    } else {
        writeln!(w, "스냅샷 정보: 없음 (출처 미확인)")?;
    }
    Ok(())
}
fn render_report_metadata(
    w: &mut BoundedWriter,
    r: &QuickRunReport,
    retained: usize,
    filtered: usize,
    selected: usize,
) -> io::Result<()> {
    writeln!(
        w,
        "=== 제공된 완료 보고서의 통계 (현재 실행의 중간 진척 아님) ==="
    )?;
    writeln!(w, "실행 취소 여부 (cancelled): {}", r.cancelled)?;
    writeln!(
        w,
        "취소 원인은 이 필드만으로 구분하지 않음 (사용자 요청·한도·실행 오류 가능)"
    )?;
    writeln!(
        w,
        "결과 바이트 한도 도달 여부 (limit_reached): {}",
        r.limit_reached
    )?;
    writeln!(
        w,
        "코어 누락 결과 수 (omitted_results): {}건",
        r.omitted_results
    )?;
    writeln!(
        w,
        "보관된 결과 직렬화 크기 (serialized_result_bytes): {} 바이트",
        r.serialized_result_bytes
    )?;
    writeln!(
        w,
        "진단 시작 대상 수 (targets_started): {}개",
        r.targets_started
    )?;
    writeln!(
        w,
        "진단 완료 대상 수 (targets_completed): {}개",
        r.targets_completed
    )?;
    writeln!(
        w,
        "최대 동시 활성 대상 수 (max_active_targets): {}개",
        r.max_active_targets
    )?;
    writeln!(w, "TCP 연결 (tcp_connect): {}회", r.invocations.tcp_connect)?;
    writeln!(w, "ICMP Ping (icmp_ping): {}회", r.invocations.icmp_ping)?;
    writeln!(
        w,
        "ICMP Traceroute (icmp_traceroute): {}회",
        r.invocations.icmp_traceroute
    )?;
    writeln!(w, "DNS 해석 (dns_lookup): {}회", r.invocations.dns_lookup)?;
    writeln!(
        w,
        "로컬 네트워크 정보 (local_network): {}회",
        r.invocations.local_network
    )?;
    for (i, error) in r.errors.iter().enumerate() {
        write!(w, "[{}] ", i + 1)?;
        stream_json!(w, error)?;
        writeln!(w)?;
    }
    writeln!(
        w,
        "코어 보관 전체 결과 행 수 (retained_count): {retained}건"
    )?;
    writeln!(
        w,
        "UI 필터 제외 결과 행 수 (filtered_out_count): {filtered}건"
    )?;
    writeln!(w, "현재 화면 표시 대상 행 수 (selected_rows): {selected}건")?;
    write!(w, "report_metadata=")?;
    write_report_meta(w, r)?;
    writeln!(w)
}
fn render_row(w: &mut BoundedWriter, index: usize, r: &QuickResult) -> io::Result<()> {
    writeln!(w, "[결과 행 #{index}]")?;
    writeln!(w, "기능: {}", feature_display_ko(r.feature))?;
    writeln!(w, "상태: {}", status_display(r.status))?;
    writeln!(w, "근거 수준: {}", evidence_display(r.evidence_level))?;
    json_field!(w, "해석된 IP", &r.resolved_ip)?;
    json_field!(w, "출발지 호스트", &r.source_host)?;
    json_field!(w, "타임스탬프", &r.timestamp_iso8601)?;
    writeln!(w, "원본 DTO (JSON):")?;
    write!(w, "result[{index}]=")?;
    stream_json!(w, r)?;
    writeln!(w)
}
fn render_body(
    w: &mut BoundedWriter,
    view: &ResultView<'_>,
    snapshot: Option<&RunSnapshot>,
    phase: RunPhase,
    rows: &mut usize,
) -> io::Result<()> {
    writeln!(w, "=== Network Quick Check 진단 결과 요약 ===")?;
    writeln!(w, "실행 단계: {}", phase_display_ko(phase))?;
    let busy = matches!(phase, RunPhase::Running | RunPhase::Cancelling);
    if busy && !matches!(view, ResultView::NotRun) {
        writeln!(
            w,
            "주의: 제공된 완료 자료는 이전 실행의 결과일 수 있으며 현재 실행의 중간 결과가 아닙니다."
        )?;
    }
    render_snapshot(w, snapshot)?;
    match view {
        ResultView::NotRun => {
            if busy {
                writeln!(
                    w,
                    "완료 결과 소스: NotRun (현재 실행의 완료 결과는 아직 없음)"
                )?;
            } else {
                writeln!(w, "진단 미실행 (NotRun)")?;
            }
        }
        ResultView::RunErrors(errors) => {
            writeln!(w, "=== 제공된 완료 오류 자료 ===")?;
            writeln!(w, "오류 건수: {}건", errors.len())?;
            if errors.is_empty() {
                writeln!(w, "오류 목록: [] (오류 내용 없음)")?;
            }
            for (i, error) in errors.iter().enumerate() {
                write!(w, "[{}] ", i + 1)?;
                stream_json!(w, error)?;
                writeln!(w)?;
            }
            write!(w, "run_errors=")?;
            stream_json!(w, *errors)?;
            writeln!(w)?;
        }
        ResultView::Report {
            report,
            selected_rows,
            retained_count,
            filtered_out_count,
        } => {
            render_report_metadata(
                w,
                report,
                *retained_count,
                *filtered_out_count,
                selected_rows.len(),
            )?;
            if selected_rows.is_empty() {
                writeln!(w, "선택된 진단 결과 행이 없습니다 (0건).")?;
            }
            for (index, row) in selected_rows {
                let checkpoint = w.buffer.len();
                if let Err(error) = render_row(w, *index, row) {
                    w.buffer.truncate(checkpoint);
                    return Err(error);
                }
                *rows += 1;
            }
        }
    }
    Ok(())
}
/// 실행 phase와 제공된 완료 자료를 분리하고, 일치 귀속은 caller에 맡긴다.
/// max_bytes는 최종 UTF-8 화면 문자열의 byte 한도이며 프로세스 전체 메모리/OS 성능 보장이 아니다.
pub fn render_final_result(
    view: &ResultView<'_>,
    snapshot: Option<&RunSnapshot>,
    phase: RunPhase,
    max_bytes: usize,
) -> RenderedResult {
    let mut w = BoundedWriter::new(max_bytes);
    let mut displayed_rows = 0;
    if render_body(&mut w, view, snapshot, phase, &mut displayed_rows).is_err() {
        w.truncated = true;
    }
    let (text, truncated) = w.finish();
    RenderedResult {
        text,
        truncated,
        displayed_rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::quick::{
        EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickFeature, QuickStatus,
    };
    use network_core::runner::ProbeCounts;
    use network_core::targets::QuickOptions;

    /// 테스트용 QuickResult 합성 생성 헬퍼.
    fn make_test_result(
        host: &str,
        resolved_ip: Option<&str>,
        port: u16,
        feature: QuickFeature,
        status: QuickStatus,
        evidence: EvidenceLevel,
    ) -> QuickResult {
        QuickResult {
            schema_version: QUICK_SCHEMA_VERSION.to_string(),
            product: QUICK_PRODUCT_NAME.to_string(),
            session_id: "test-session".to_string(),
            timestamp_iso8601: Some("2026-10-26T12:00:00Z".to_string()),
            source_host: Some("client.local".to_string()),
            target_host: host.to_string(),
            resolved_ip: resolved_ip.map(|s| s.to_string()),
            target_port: port,
            feature,
            status,
            elapsed_ms: Some(15),
            os_error_code: None,
            details: serde_json::json!({
                "outcome": "CONNECTED",
                "limitations": ["테스트 제약사항"],
                "raw_measurement": { "bytes_sent": 64 }
            }),
            evidence_level: evidence,
        }
    }

    /// 테스트용 QuickRunReport 합성 생성 헬퍼.
    fn make_test_report(results: Vec<QuickResult>) -> QuickRunReport {
        QuickRunReport {
            results,
            cancelled: false,
            limit_reached: false,
            omitted_results: 3,
            errors: vec!["주의: ICMP 응답 지연".to_string()],
            invocations: ProbeCounts {
                tcp_connect: 2,
                icmp_ping: 1,
                local_network: 1,
                dns_lookup: 2,
                icmp_traceroute: 0,
            },
            max_active_targets: 2,
            targets_started: 2,
            targets_completed: 2,
            serialized_result_bytes: 1024,
        }
    }

    #[test]
    fn test_render_not_run_all_phases() {
        let phases = [
            RunPhase::Ready,
            RunPhase::Running,
            RunPhase::Cancelling,
            RunPhase::Finished,
        ];

        for phase in phases {
            let rendered = render_final_result(&ResultView::NotRun, None, phase, 10000);
            assert!(!rendered.truncated);
            assert_eq!(rendered.displayed_rows, 0);
            assert!(rendered.text.contains("실행 단계:"));
            assert!(rendered.text.contains(
                if matches!(phase, RunPhase::Running | RunPhase::Cancelling) {
                    "NotRun (현재 실행의 완료 결과는 아직 없음)"
                } else {
                    "진단 미실행 (NotRun)"
                }
            ));
            assert!(rendered.text.contains("스냅샷 정보: 없음"));
            assert!(rendered.text.len() <= 10000);
        }
    }

    #[test]
    fn test_render_run_errors_empty_and_populated() {
        let empty_errors: Vec<String> = Vec::new();
        let rendered_empty = render_final_result(
            &ResultView::RunErrors(&empty_errors),
            None,
            RunPhase::Finished,
            10000,
        );
        assert!(!rendered_empty.truncated);
        assert_eq!(rendered_empty.displayed_rows, 0);
        assert!(rendered_empty.text.contains("오류 건수: 0건"));
        assert!(
            rendered_empty
                .text
                .contains("오류 목록: [] (오류 내용 없음)")
        );

        let populated_errors = vec![
            "DNS 해석 실패: 10.0.0.1".to_string(),
            "소켓 생성 거부".to_string(),
            "DNS 해석 실패: 10.0.0.1".to_string(),
        ];
        let rendered_populated = render_final_result(
            &ResultView::RunErrors(&populated_errors),
            None,
            RunPhase::Finished,
            10000,
        );
        assert!(!rendered_populated.truncated);
        assert_eq!(rendered_populated.displayed_rows, 0);
        assert!(rendered_populated.text.contains("오류 건수: 3건"));
        assert!(
            rendered_populated
                .text
                .contains("[1] \"DNS 해석 실패: 10.0.0.1\"")
        );
        assert!(rendered_populated.text.contains("[2] \"소켓 생성 거부\""));
        assert!(
            rendered_populated
                .text
                .contains("[3] \"DNS 해석 실패: 10.0.0.1\"")
        );
    }

    #[test]
    fn test_render_report_empty() {
        let report = make_test_report(Vec::new());
        let view = ResultView::Report {
            report: &report,
            selected_rows: Vec::new(),
            retained_count: 0,
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 10000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 0);
        assert!(
            rendered
                .text
                .contains("선택된 진단 결과 행이 없습니다 (0건)")
        );
        assert!(
            rendered
                .text
                .contains("코어 누락 결과 수 (omitted_results): 3건")
        );
        assert!(rendered.text.contains("TCP 연결 (tcp_connect): 2회"));
    }

    #[test]
    fn test_render_all_status_and_evidence_independence() {
        let statuses = [
            QuickStatus::PASS,
            QuickStatus::FAIL,
            QuickStatus::WARN,
            QuickStatus::SKIPPED,
            QuickStatus::UNKNOWN,
        ];
        let evidences = [
            EvidenceLevel::OBSERVED,
            EvidenceLevel::INFERRED,
            EvidenceLevel::UNKNOWN,
        ];

        let mut results = Vec::new();
        for (i, &status) in statuses.iter().enumerate() {
            let evidence = evidences[i % evidences.len()];
            results.push(make_test_result(
                "example.com",
                Some("93.184.216.34"),
                80,
                QuickFeature::TcpConnect,
                status,
                evidence,
            ));
        }

        let report = make_test_report(results);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: report.results.len(),
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 20000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 5);

        assert!(rendered.text.contains("PASS (성공)"));
        assert!(rendered.text.contains("FAIL (실패)"));
        assert!(rendered.text.contains("WARN (경고)"));
        assert!(rendered.text.contains("SKIPPED (미실행)"));
        assert!(rendered.text.contains("UNKNOWN (확인불가)"));

        assert!(rendered.text.contains("OBSERVED (관측)"));
        assert!(rendered.text.contains("INFERRED (추론)"));
        assert!(rendered.text.contains("UNKNOWN (미확인)"));
    }

    #[test]
    fn test_null_vs_string_null() {
        let mut res1 = make_test_result(
            "host1",
            None,
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        res1.resolved_ip = None;
        res1.source_host = None;
        res1.timestamp_iso8601 = None;

        let mut res2 = make_test_result(
            "host2",
            Some("null"),
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        res2.resolved_ip = Some("null".to_string());
        res2.source_host = Some("null".to_string());
        res2.timestamp_iso8601 = Some("null".to_string());

        let report = make_test_report(vec![res1, res2]);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 2,
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 20000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 2);

        assert!(rendered.text.contains("해석된 IP: null\n"));
        assert!(rendered.text.contains("출발지 호스트: null\n"));
        assert!(rendered.text.contains("타임스탬프: null\n"));

        assert!(rendered.text.contains("해석된 IP: \"null\"\n"));
        assert!(rendered.text.contains("출발지 호스트: \"null\"\n"));
        assert!(rendered.text.contains("타임스탬프: \"null\"\n"));

        assert!(rendered.text.contains("\"resolved_ip\":null"));
        assert!(rendered.text.contains("\"resolved_ip\":\"null\""));
    }

    #[test]
    fn test_special_characters_and_nul_safety() {
        let mut res = make_test_result(
            "한글과이모지🚀\0호스트",
            Some("192.168.1.1"),
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        res.details = serde_json::json!({
            "quote": "큰따옴표\"와역슬래시\\및개행\r\n",
            "embedded_nul": "중간\0널문자"
        });

        let report = make_test_report(vec![res]);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 1,
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 20000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 1);

        assert!(!rendered.text.as_bytes().contains(&0));
        assert!(rendered.text.contains("한글과이모지🚀\\u0000호스트"));
        assert!(std::str::from_utf8(rendered.text.as_bytes()).is_ok());
    }

    #[test]
    fn test_report_metadata_and_dto_all_14_fields() {
        let res = make_test_result(
            "target.internal",
            Some("10.0.0.5"),
            443,
            QuickFeature::TcpConnect,
            QuickStatus::WARN,
            EvidenceLevel::INFERRED,
        );
        let mut report = make_test_report(vec![res]);
        report.cancelled = true;
        report.limit_reached = true;
        report.omitted_results = 42;
        report.serialized_result_bytes = 4096;
        report.targets_started = 5;
        report.targets_completed = 4;
        report.max_active_targets = 3;
        report.invocations = ProbeCounts {
            tcp_connect: 10,
            icmp_ping: 8,
            icmp_traceroute: 2,
            dns_lookup: 5,
            local_network: 1,
        };
        report.errors = vec!["경고: 메모리 절약 한도 도달".to_string()];

        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 1,
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 30000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 1);

        assert!(rendered.text.contains("실행 취소 여부 (cancelled): true"));
        assert!(
            rendered
                .text
                .contains("결과 바이트 한도 도달 여부 (limit_reached): true")
        );
        assert!(
            rendered
                .text
                .contains("코어 누락 결과 수 (omitted_results): 42건")
        );
        assert!(
            rendered
                .text
                .contains("보관된 결과 직렬화 크기 (serialized_result_bytes): 4096 바이트")
        );
        assert!(
            rendered
                .text
                .contains("진단 시작 대상 수 (targets_started): 5개")
        );
        assert!(
            rendered
                .text
                .contains("진단 완료 대상 수 (targets_completed): 4개")
        );
        assert!(
            rendered
                .text
                .contains("최대 동시 활성 대상 수 (max_active_targets): 3개")
        );
        assert!(rendered.text.contains("TCP 연결 (tcp_connect): 10회"));
        assert!(rendered.text.contains("ICMP Ping (icmp_ping): 8회"));
        assert!(
            rendered
                .text
                .contains("ICMP Traceroute (icmp_traceroute): 2회")
        );
        assert!(rendered.text.contains("DNS 해석 (dns_lookup): 5회"));
        assert!(
            rendered
                .text
                .contains("로컬 네트워크 정보 (local_network): 1회")
        );
        assert!(
            rendered
                .text
                .contains("[1] \"경고: 메모리 절약 한도 도달\"")
        );

        assert!(rendered.text.contains("\"schema_version\":"));
        assert!(rendered.text.contains("\"product\":"));
        assert!(rendered.text.contains("\"session_id\":"));
        assert!(rendered.text.contains("\"timestamp_iso8601\":"));
        assert!(rendered.text.contains("\"source_host\":"));
        assert!(rendered.text.contains("\"target_host\":"));
        assert!(rendered.text.contains("\"resolved_ip\":"));
        assert!(rendered.text.contains("\"target_port\":"));
        assert!(rendered.text.contains("\"feature\":"));
        assert!(rendered.text.contains("\"status\":"));
        assert!(rendered.text.contains("\"elapsed_ms\":"));
        assert!(rendered.text.contains("\"os_error_code\":"));
        assert!(rendered.text.contains("\"details\":"));
        assert!(rendered.text.contains("\"evidence_level\":"));
    }

    #[test]
    fn test_filter_view_separation() {
        let res1 = make_test_result(
            "host1",
            Some("10.0.0.1"),
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        let res2 = make_test_result(
            "host2",
            Some("10.0.0.2"),
            80,
            QuickFeature::TcpConnect,
            QuickStatus::FAIL,
            EvidenceLevel::OBSERVED,
        );
        let report = make_test_report(vec![res1, res2]);

        let selected_rows = vec![(1usize, &report.results[1])];
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 2,
            filtered_out_count: 1,
        };

        let rendered = render_final_result(&view, None, RunPhase::Finished, 20000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 1);

        assert!(
            rendered
                .text
                .contains("코어 보관 전체 결과 행 수 (retained_count): 2건")
        );
        assert!(
            rendered
                .text
                .contains("UI 필터 제외 결과 행 수 (filtered_out_count): 1건")
        );
        assert!(
            rendered
                .text
                .contains("현재 화면 표시 대상 행 수 (selected_rows): 1건")
        );
        assert!(
            rendered
                .text
                .contains("코어 누락 결과 수 (omitted_results): 3건")
        );

        assert!(!rendered.text.contains("[결과 행 #0]"));
        assert!(rendered.text.contains("[결과 행 #1]"));
    }

    #[test]
    fn test_budget_caps_zero_and_small() {
        let res = make_test_result(
            "target.example",
            Some("1.1.1.1"),
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        let report = make_test_report(vec![res]);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 1,
            filtered_out_count: 0,
        };

        let caps = [
            0,
            1,
            2,
            5,
            20,
            TRUNCATION_MARKER.len() - 1,
            TRUNCATION_MARKER.len(),
            TRUNCATION_MARKER.len() + 10,
        ];
        for cap in caps {
            let rendered = render_final_result(&view, None, RunPhase::Finished, cap);
            assert!(
                rendered.text.len() <= cap,
                "cap {} 초과: 실제 바이트 len = {}",
                cap,
                rendered.text.len()
            );
            assert!(rendered.truncated);
            assert_eq!(rendered.displayed_rows, 0);
            assert!(std::str::from_utf8(rendered.text.as_bytes()).is_ok());
            assert!(!rendered.text.as_bytes().contains(&0));
        }
    }

    #[test]
    fn test_budget_exhaustion_midway_and_displayed_rows() {
        let mut results = Vec::new();
        for i in 0..10 {
            results.push(make_test_result(
                &format!("host{}.example.com", i),
                Some("10.0.0.1"),
                80,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ));
        }

        let report = make_test_report(results);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 10,
            filtered_out_count: 0,
        };

        let full_rendered = render_final_result(&view, None, RunPhase::Finished, 100000);
        assert!(!full_rendered.truncated);
        assert_eq!(full_rendered.displayed_rows, 10);
        let full_len = full_rendered.text.len();

        let restricted_cap = full_len / 3;
        let restricted_rendered =
            render_final_result(&view, None, RunPhase::Finished, restricted_cap);

        assert!(restricted_rendered.text.len() <= restricted_cap);
        assert!(restricted_rendered.truncated);
        assert!(restricted_rendered.displayed_rows < 10);
        assert!(restricted_rendered.text.contains(TRUNCATION_MARKER.trim()));
        assert!(std::str::from_utf8(restricted_rendered.text.as_bytes()).is_ok());
        assert!(!restricted_rendered.text.as_bytes().contains(&0));
    }

    #[test]
    fn test_render_with_active_snapshot() {
        let mut state = crate::gui_state::GuiState::new();
        state.replace_targets("127.0.0.1:8080").unwrap();
        let snapshot = state.begin_run().unwrap();

        let res = make_test_result(
            "127.0.0.1",
            Some("127.0.0.1"),
            8080,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        let report = make_test_report(vec![res]);
        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 1,
            filtered_out_count: 0,
        };

        let rendered = render_final_result(&view, Some(&snapshot), RunPhase::Finished, 30000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 1);

        assert!(rendered.text.contains("실행 식별자 (RunId): 1"));
        assert!(rendered.text.contains("세션 ID: \"gui-run-1\""));
        assert!(rendered.text.contains("요청 대상 수: 1개"));
        assert!(rendered.text.contains("TCP 타임아웃: 3000 ms"));
        assert!(rendered.text.contains("진단 계획 (QuickPlan):"));
        assert!(rendered.text.contains("계획된 대상 수: 1개"));
    }

    #[test]
    fn test_inputs_immutability() {
        let mut state = crate::gui_state::GuiState::new();
        state.replace_targets("127.0.0.1:8080").unwrap();
        let snapshot = state.begin_run().unwrap();

        let res = make_test_result(
            "127.0.0.1",
            Some("127.0.0.1"),
            8080,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        let report = make_test_report(vec![res]);
        let original_report = report.clone();
        let original_snapshot = snapshot.clone();

        let selected_rows: Vec<(usize, &QuickResult)> = report.results.iter().enumerate().collect();
        let view = ResultView::Report {
            report: &report,
            selected_rows,
            retained_count: 1,
            filtered_out_count: 0,
        };

        let _ = render_final_result(&view, Some(&snapshot), RunPhase::Finished, 50);

        assert_eq!(report, original_report);
        assert_eq!(snapshot, original_snapshot);
    }
    fn parent_json_line(text: &str, prefix: &str) -> serde_json::Value {
        let row = text
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("원문 JSON 행 존재");
        serde_json::from_str(row).expect("완전한 원문 JSON")
    }
    #[test]
    fn parent_all_snapshot_targets_options_plan_fields_equal_source() {
        use crate::gui_state::GuiState;
        for ping in [false, true] {
            let mut s = GuiState::new();
            s.replace_targets("MiXeD.Example:080\n[::1]:443\n127.0.0.1:1521")
                .unwrap();
            let mut features = vec![QuickFeature::LocalNetwork, QuickFeature::TcpConnect];
            if ping {
                features.push(QuickFeature::IcmpPing);
            }
            s.set_options(QuickOptions {
                tcp_timeout_ms: 777,
                concurrency: 1,
                selected_features: features,
            })
            .unwrap();
            let snap = s.begin_run().unwrap();
            let r = make_test_report(vec![]);
            let source = Ok(r);
            let view = crate::result_view::build_result_view(Some(&source), &Default::default());
            let rendered = render_final_result(&view, Some(&snap), RunPhase::Finished, 100_000);
            assert!(!rendered.truncated);
            let raw = parent_json_line(&rendered.text, "snapshot_raw=");
            let req = snap.request();
            let plan = snap.plan();
            let targets: Vec<_> = req
                .targets
                .iter()
                .map(|t| serde_json::json!({"host":t.host,"port":t.port,"raw_input":t.raw_input}))
                .collect();
            let planned:Vec<_>=plan.targets.iter().map(|p|serde_json::json!({"target":{"host":p.target.host,"port":p.target.port,"raw_input":p.target.raw_input},
                "features":p.features,"requires_resolution":p.requires_resolution})).collect();
            assert_eq!(
                raw,
                serde_json::json!({"run_id":snap.run_id().as_u64(),
                "request":{"session_id":req.session_id,"timestamp_iso8601":req.timestamp_iso8601,"source_host":req.source_host,
                  "targets":targets,"options":{"tcp_timeout_ms":req.options.tcp_timeout_ms,"concurrency":req.options.concurrency,"selected_features":req.options.selected_features},"max_result_bytes":req.max_result_bytes},
                "plan":{"targets":planned,"tcp_timeout_ms":plan.tcp_timeout_ms,"icmp_timeout_ms":plan.icmp_timeout_ms,"concurrency":plan.concurrency,"limitations":plan.limitations}})
            );
            assert_eq!(req.targets[0].raw_input, "MiXeD.Example:080");
            assert!(plan.targets[0].requires_resolution);
            assert!(!plan.targets[1].requires_resolution);
            assert_eq!(plan.icmp_timeout_ms.is_some(), ping);
        }
    }
    #[test]
    fn parent_all_report_metadata_and_full_json_values_equal_source() {
        let mut row = make_test_result(
            "한글🚀",
            None,
            443,
            QuickFeature::TcpConnect,
            QuickStatus::UNKNOWN,
            EvidenceLevel::INFERRED,
        );
        row.timestamp_iso8601 = None;
        row.source_host = Some("null".into());
        row.os_error_code = Some(10061);
        row.elapsed_ms = Some(0);
        row.details = serde_json::json!({"outcome":"미확인","raw":{"arr":[null,"null","A\0B","A\\u0000B","중복","중복"],"nested":{"v":-3}},"limitations":["동일","동일"]});
        let mut report = make_test_report(vec![row.clone(), row]);
        report.cancelled = true;
        report.limit_reached = true;
        report.errors = vec!["E\0\r\n🚀".into(), "E\0\r\n🚀".into()];
        report.omitted_results = 31;
        report.invocations = ProbeCounts {
            tcp_connect: 3,
            icmp_ping: 5,
            local_network: 7,
            dns_lookup: 11,
            icmp_traceroute: 13,
        };
        let source = Ok(report.clone());
        let view = crate::result_view::build_result_view(Some(&source), &Default::default());
        let rendered = render_final_result(&view, None, RunPhase::Finished, 100_000);
        assert!(!rendered.truncated);
        assert_eq!(rendered.displayed_rows, 2);
        let mut expected = serde_json::to_value(&report).unwrap();
        expected.as_object_mut().unwrap().remove("results");
        assert_eq!(
            parent_json_line(&rendered.text, "report_metadata="),
            expected
        );
        for (index, row) in report.results.iter().enumerate() {
            assert_eq!(
                parent_json_line(&rendered.text, &format!("result[{index}]=")),
                serde_json::to_value(row).unwrap()
            );
        }
        assert_eq!(source, Ok(report));
        assert!(!rendered.text.contains('\0'));
    }
    #[test]
    fn parent_busy_report_and_errors_are_completed_material_not_progress() {
        let mut s = crate::gui_state::GuiState::new();
        s.replace_targets("127.0.0.1:80").unwrap();
        let first = s.begin_run().unwrap();
        let report = make_test_report(vec![]);
        s.finish_run(first.run_id(), Ok(report.clone())).unwrap();
        s.replace_targets("[::1]:443").unwrap();
        let active = s.begin_run().unwrap();
        assert_ne!(active.run_id(), first.run_id());
        let report_source = Ok(report);
        let error_source = Err(vec!["이전 실행 오류".into()]);
        for source in [&report_source, &error_source] {
            let view = crate::result_view::build_result_view(Some(source), &Default::default());
            for phase in [RunPhase::Running, RunPhase::Cancelling] {
                let rendered = render_final_result(&view, Some(&active), phase, 30_000);
                assert!(
                    rendered
                        .text
                        .contains("이전 실행의 결과일 수 있으며 현재 실행의 중간 결과가 아닙니다")
                );
                assert!(rendered.text.contains("동일 실행 귀속은 caller 책임"));
                assert!(!rendered.text.contains("진행률: 100"));
            }
        }
    }
    #[test]
    fn parent_json_string_null_nul_backslash_and_nullable_metadata_are_reversible() {
        let errors = vec![
            "A\0B".into(),
            "A\\u0000B".into(),
            "\"\\\r\n🚀".into(),
            "null (미확인)".into(),
        ];
        let output = render_final_result(
            &ResultView::RunErrors(&errors),
            None,
            RunPhase::Finished,
            20_000,
        );
        assert_eq!(
            parent_json_line(&output.text, "run_errors="),
            serde_json::to_value(&errors).unwrap()
        );
        assert!(!output.text.contains('\0'));
        let mut state = crate::gui_state::GuiState::new();
        state.replace_targets("127.0.0.1:80").unwrap();
        let snap = state.begin_run().unwrap();
        // public snapshot을 변경하지 않는다. 실제 request 직렬화와 같은 private adapter의 Option 경계를 검증한다.
        let mut request = snap.request().clone();
        for value in [
            None,
            Some("null (미확인)".to_owned()),
            Some("A\0B".to_owned()),
            Some("A\\u0000B".to_owned()),
        ] {
            request.source_host = value.clone();
            request.timestamp_iso8601 = value.clone();
            let mut writer = BoundedWriter::new(10_000);
            write_request(&mut writer, &request).unwrap();
            let (text, truncated) = writer.finish();
            assert!(!truncated);
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed["source_host"], serde_json::to_value(&value).unwrap());
            assert_eq!(
                parsed["timestamp_iso8601"],
                serde_json::to_value(&value).unwrap()
            );
            assert!(!text.contains('\0'));
        }
    }
    #[test]
    fn parent_cap_error_short_circuits_serialization_and_subsequent_writes() {
        for cap in [
            0,
            1,
            TRUNCATION_MARKER.len() + 10,
            TRUNCATION_MARKER.len() + 100,
        ] {
            let visits = std::cell::Cell::new(0);
            let mut writer = BoundedWriter::new(cap);
            let target = QuickTarget {
                host: "🚀\\\"\0".repeat(200),
                port: 80,
                raw_input: "합성 경계".into(),
            };
            let counted =
                std::iter::repeat_n(&target, 10_000).inspect(|_| visits.set(visits.get() + 1));
            assert!(write_targets(&mut writer, counted).is_err());
            assert!(visits.get() <= 1, "정지 후 후속 element 방문 금지");
            assert!(writer.write_all(b"later").is_err());
            let (text, truncated) = writer.finish();
            assert!(truncated);
            assert!(text.len() <= cap);
            assert!(!text.contains('\0'));
        }
    }
    #[test]
    fn parent_exact_completed_row_count_and_rollback_at_each_boundary() {
        let report = make_test_report(
            (0..3)
                .map(|i| {
                    make_test_result(
                        &format!("h{i}🚀"),
                        None,
                        80,
                        QuickFeature::TcpConnect,
                        QuickStatus::PASS,
                        EvidenceLevel::OBSERVED,
                    )
                })
                .collect(),
        );
        let source = Ok(report);
        let view = crate::result_view::build_result_view(Some(&source), &Default::default());
        let full = render_final_result(&view, None, RunPhase::Finished, 100_000);
        assert!(!full.truncated);
        let end = full.text.find("[결과 행 #1]").unwrap();
        for (cap, expected) in [
            (end + TRUNCATION_MARKER.len() - 1, 0),
            (end + TRUNCATION_MARKER.len(), 1),
            (end + TRUNCATION_MARKER.len() + 1, 1),
        ] {
            let output = render_final_result(&view, None, RunPhase::Finished, cap);
            assert!(output.truncated);
            assert_eq!(output.displayed_rows, expected);
            let complete = output
                .text
                .lines()
                .filter(|line| line.starts_with("result["))
                .count();
            assert_eq!(complete, expected);
            assert!(output.text.len() <= cap);
            assert!(!output.text.contains("[결과 행 #1]"));
        }
        for cap in 0..=TRUNCATION_MARKER.len() + 80 {
            let output = render_final_result(&view, None, RunPhase::Finished, cap);
            assert!(output.truncated);
            assert_eq!(output.displayed_rows, 0);
            assert!(output.text.len() <= cap);
        }
    }
    #[test]
    fn parent_selection_order_duplicate_indices_and_originals_are_preserved() {
        let report = make_test_report(
            (0..3)
                .map(|i| {
                    make_test_result(
                        &format!("row{i}"),
                        None,
                        80,
                        QuickFeature::TcpConnect,
                        QuickStatus::WARN,
                        EvidenceLevel::UNKNOWN,
                    )
                })
                .collect(),
        );
        let before = report.clone();
        let view = ResultView::Report {
            report: &report,
            selected_rows: vec![
                (2, &report.results[2]),
                (0, &report.results[0]),
                (2, &report.results[2]),
            ],
            retained_count: 3,
            filtered_out_count: 0,
        };
        let out = render_final_result(&view, None, RunPhase::Finished, 50_000);
        assert!(!out.truncated);
        assert_eq!(out.displayed_rows, 3);
        let rows: Vec<_> = out
            .text
            .lines()
            .filter(|s| s.starts_with("result["))
            .collect();
        assert!(rows[0].starts_with("result[2]="));
        assert!(rows[1].starts_with("result[0]="));
        assert!(rows[2].starts_with("result[2]="));
        assert_eq!(rows[0], rows[2]);
        assert_eq!(report, before);
    }
    #[test]
    fn parent_large_metadata_raw_escape_expansion_and_mid_json_caps_keep_sources() {
        let mut row = make_test_result(
            "巨大🚀",
            None,
            80,
            QuickFeature::TcpConnect,
            QuickStatus::UNKNOWN,
            EvidenceLevel::UNKNOWN,
        );
        row.details = serde_json::json!({"raw":{"nested":["\0\"\\🚀".repeat(30_000),null]}});
        let mut report = make_test_report(vec![row.clone()]);
        let mut state = crate::gui_state::GuiState::new();
        state
            .replace_targets("MiXeD.Example:080\n[::1]:443\n127.0.0.1:80")
            .unwrap();
        let snap = state.begin_run().unwrap();
        let original_snap = snap.clone();
        for big_errors in [false, true] {
            if big_errors {
                report.errors = vec!["\0\r\n\\\"🚀".repeat(5_000); 3];
            } else {
                report.errors.clear();
            }
            let source = Ok(report.clone());
            let view = crate::result_view::build_result_view(Some(&source), &Default::default());
            for cap in [0, 128, 512, 2048, 8192, 16_384] {
                let output = render_final_result(&view, Some(&snap), RunPhase::Finished, cap);
                assert!(output.truncated);
                assert_eq!(output.displayed_rows, 0);
                assert!(output.text.len() <= cap);
                assert!(!output.text.contains('\0'));
                assert_eq!(source, Ok(report.clone()));
                assert_eq!(snap, original_snap);
            }
        }
    }
    #[test]
    fn parent_all_feature_status_evidence_combinations_keep_full_original_json() {
        let mut rows = vec![];
        for f in [
            QuickFeature::TcpConnect,
            QuickFeature::IcmpPing,
            QuickFeature::IcmpTraceroute,
            QuickFeature::DnsLookup,
            QuickFeature::LocalNetwork,
        ] {
            for s in [
                QuickStatus::PASS,
                QuickStatus::FAIL,
                QuickStatus::WARN,
                QuickStatus::SKIPPED,
                QuickStatus::UNKNOWN,
            ] {
                for e in [
                    EvidenceLevel::OBSERVED,
                    EvidenceLevel::INFERRED,
                    EvidenceLevel::UNKNOWN,
                ] {
                    rows.push(make_test_result("합성보존", None, 443, f, s, e));
                }
            }
        }
        let report = make_test_report(rows);
        let source = Ok(report.clone());
        let view = crate::result_view::build_result_view(Some(&source), &Default::default());
        let output = render_final_result(&view, None, RunPhase::Finished, 262_144);
        assert!(!output.truncated);
        assert_eq!(output.displayed_rows, report.results.len());
        for (index, row) in report.results.iter().enumerate() {
            assert_eq!(
                parent_json_line(&output.text, &format!("result[{index}]=")),
                serde_json::to_value(row).unwrap()
            );
        }
    }

    #[test]
    fn parent_system_cancelled_flag_does_not_imply_user_request() {
        // 합성 한도/오류 자료를 표시할 뿐 실제 측정 또는 사용자 취소 관측이 아니다.
        for limit in [false, true] {
            let mut report = make_test_report(vec![]);
            report.cancelled = true;
            report.limit_reached = limit;
            report.errors = if limit {
                vec![]
            } else {
                vec!["합성 작업 오류로 인한 정리".into()]
            };
            let source = Ok(report);
            let view = crate::result_view::build_result_view(Some(&source), &Default::default());
            let output = render_final_result(&view, None, RunPhase::Finished, 20_000);
            assert!(!output.truncated);
            assert!(output.text.contains("실행 취소 여부 (cancelled): true"));
            assert!(
                output
                    .text
                    .contains("취소 원인은 이 필드만으로 구분하지 않음")
            );
            assert!(!output.text.contains("사용자 취소 여부"));
            let raw = parent_json_line(&output.text, "report_metadata=");
            assert_eq!(raw["cancelled"], true);
            assert_eq!(raw["limit_reached"], limit);
        }
    }
}
