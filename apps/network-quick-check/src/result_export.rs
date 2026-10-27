//! Network Quick Check(Part B) 진단 결과 순수 내보내기(TXT/CSV) 인코딩 모듈.
//!
//! 본 모듈은 진단 실행 결과(`QuickRunReport`) 및 실행 컨텍스트(`ExportContext`)를
//! 메모리 상의 정밀한 TXT 및 RFC 4180 호환 CSV 바이트(`Vec<u8>`)로 직렬화합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **완전한 순수성(Purity)**: I/O, Win32, 파일 쓰기, 클립보드, 시계, 환경변수, 스레드, 비동기 런타임 배제.
//! - **메모리 한도 즉시 집행(Bounded Streaming)**: 거대 객체를 메모리에 선행 조립(to_string, to_vec, format!)한 후
//!   사후 절삭(truncate)하는 방식을 엄격히 금지하며, `BoundedWriter`를 통해 작성 도중부터 바이트 한도(`max_bytes`)를 집행합니다.
//! - **단일 진실 공급원 및 원문 보존**: Core `QuickResult` 14개 필드와 `QuickRunReport` 실제 필드를 왜곡 없이 직렬화하며,
//!   `details`, `raw_measurement`, 원문 개행(CRLF), 한글/이모지, 수식 문자를 정확히 보존합니다.
//! - **CSV 수식 주입 방지(Formula Injection Protection)**: 모든 데이터 셀 앞에 ASCII 작은따옴표(`'`)를
//!   정확히 1개 추가한 후 RFC 4180 큰따옴표 이스케이프를 적용합니다 (헤더 셀은 따옴표만 적용).
//! - **독립 실행 스냅샷 귀속**: `ExportContext.snapshot`을 통해 실행 당시 확정된 설정(`run_id`, `request`, `plan`)을
//!   기록하며, 현재 GUI의 draft 편집 상태나 시스템 시계/호스트명으로 대체하지 않습니다.

use std::io::{self, Write};

use crate::gui_state::RunSnapshot;
use crate::result_view::{ResultFilter, select_rows};
use network_core::quick::QuickResult;
use network_core::runner::QuickRunReport;

/// CSV 고정 18열 헤더 목록.
pub const CSV_HEADERS: [&str; 18] = [
    "record_type",
    "result_index",
    "schema_version",
    "product",
    "session_id",
    "timestamp_iso8601",
    "source_host",
    "target_host",
    "resolved_ip",
    "target_port",
    "feature",
    "status",
    "elapsed_ms",
    "os_error_code",
    "details",
    "evidence_level",
    "metadata_json",
    "raw_result_json",
];

/// 진단 결과 내보내기 실행 컨텍스트.
pub struct ExportContext<'a> {
    /// 진단 실행 시작 시 확정된 불변 스냅샷 (없으면 None).
    pub snapshot: Option<&'a RunSnapshot>,
    /// 제품 실행 파일 버전 문자열 (Core product/schema와 독립된 명시적 버전).
    pub program_version: &'a str,
}

/// 결과 내보내기 대상 범위.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportScope {
    /// 필터와 무관하게 보관된 모든 진단 결과 행 내보내기.
    All,
    /// 현재 활성 필터 조건을 통과한 결과 행만 내보내기.
    Filtered,
}

/// 결과 내보내기 인코딩 중 발생하는 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// 지정된 바이트 상한을 초과하여 출력을 완료할 수 없음 (부분 출력 성공 0).
    TooLarge {
        /// 호출자가 지정한 최대 허용 바이트 한도.
        limit: usize,
    },
    /// JSON 또는 문자열 직렬화 오류.
    Serialization(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "출력 바이트 한도({limit} 바이트)를 초과했습니다.")
            }
            Self::Serialization(msg) => write!(f, "직렬화 오류: {msg}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// 바이트 상한을 엄격히 집행하는 제한된 메모리 버퍼 작성기.
pub struct BoundedWriter {
    buffer: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    /// 지정된 최대 바이트 한도를 갖는 BoundedWriter를 생성합니다.
    pub fn new(limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            limit,
        }
    }

    /// 내부 버퍼 바이트 벡터를 소비하여 반환합니다.
    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }

    /// 현재까지 기록된 바이트 수를 반환합니다.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// 현재 버퍼가 비어있는지 여부를 반환합니다.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.buffer.len());
        if remaining < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("한도 {} 바이트 초과", self.limit),
            ));
        }
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// I/O 오류를 ExportError로 변환하는 내부 헬퍼.
fn io_err_to_export_err(err: io::Error, limit: usize) -> ExportError {
    if err.kind() == io::ErrorKind::OutOfMemory {
        ExportError::TooLarge { limit }
    } else {
        ExportError::Serialization(err.to_string())
    }
}

/// CSV 헤더 셀을 RFC 4180 규칙에 따라 큰따옴표로 감싸서 작성합니다 (접두사 없음).
fn write_csv_header_cell<W: Write>(writer: &mut W, cell: &str) -> io::Result<()> {
    writer.write_all(b"\"")?;
    let bytes = cell.as_bytes();
    let mut last = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            if i > last {
                writer.write_all(&bytes[last..i])?;
            }
            writer.write_all(b"\"\"")?;
            last = i + 1;
        }
    }
    if last < bytes.len() {
        writer.write_all(&bytes[last..])?;
    }
    writer.write_all(b"\"")?;
    Ok(())
}

/// CSV 데이터 셀을 수식 주입 방지 작은따옴표(') 접두사와 함께 RFC 4180 규칙으로 작성합니다.
fn write_csv_data_cell<W: Write>(writer: &mut W, cell: &str) -> io::Result<()> {
    writer.write_all(b"\"'")?;
    let bytes = cell.as_bytes();
    let mut last = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            if i > last {
                writer.write_all(&bytes[last..i])?;
            }
            writer.write_all(b"\"\"")?;
            last = i + 1;
        }
    }
    if last < bytes.len() {
        writer.write_all(&bytes[last..])?;
    }
    writer.write_all(b"\"")?;
    Ok(())
}

/// 메타데이터 JSON을 스트림 방식으로 한도 작성기에 직접 기록합니다.
///
/// 거대한 JSON Value 전체를 힙에 할당하지 않고 각 필드를 스트리밍으로 작성합니다.
fn write_metadata_json<W: Write>(
    writer: &mut W,
    source: Option<&Result<QuickRunReport, Vec<String>>>,
    context: &ExportContext,
    filter: &ResultFilter,
    scope: ExportScope,
    selected_indices: &[usize],
) -> io::Result<()> {
    writer.write_all(b"{\"format\":\"network-quick-check-export-v1\",")?;

    writer.write_all(b"\"program_version\":")?;
    serde_json::to_writer(&mut *writer, context.program_version)?;

    let source_state = match source {
        None => "not_run",
        Some(Err(_)) => "run_errors",
        Some(Ok(_)) => "report",
    };
    writer.write_all(b",\"source_state\":")?;
    serde_json::to_writer(&mut *writer, source_state)?;

    let scope_str = match scope {
        ExportScope::All => "all",
        ExportScope::Filtered => "filtered",
    };
    writer.write_all(b",\"export_scope\":")?;
    serde_json::to_writer(&mut *writer, scope_str)?;

    // filter
    writer.write_all(b",\"filter\":{\"status\":")?;
    serde_json::to_writer(&mut *writer, &filter.status.map(|s| s.as_str()))?;
    writer.write_all(b",\"feature\":")?;
    serde_json::to_writer(&mut *writer, &filter.feature.map(|f| f.as_str()))?;
    writer.write_all(b",\"evidence_level\":")?;
    serde_json::to_writer(&mut *writer, &filter.evidence_level.map(|e| e.as_str()))?;
    writer.write_all(b",\"target_query\":")?;
    serde_json::to_writer(&mut *writer, &filter.target_query)?;
    writer.write_all(b"}")?;

    // snapshot / context_origin
    if let Some(snapshot) = context.snapshot {
        writer.write_all(b",\"context_origin\":\"supplied_run_snapshot\",")?;
        writer.write_all(b"\"run_id\":")?;
        serde_json::to_writer(&mut *writer, &snapshot.run_id().as_u64())?;

        // request
        let req = snapshot.request();
        writer.write_all(b",\"request\":{\"session_id\":")?;
        serde_json::to_writer(&mut *writer, &req.session_id)?;
        writer.write_all(b",\"timestamp_iso8601\":")?;
        serde_json::to_writer(&mut *writer, &req.timestamp_iso8601)?;
        writer.write_all(b",\"source_host\":")?;
        serde_json::to_writer(&mut *writer, &req.source_host)?;
        writer.write_all(b",\"targets\":[")?;
        for (i, t) in req.targets.iter().enumerate() {
            if i > 0 {
                writer.write_all(b",")?;
            }
            writer.write_all(b"{\"host\":")?;
            serde_json::to_writer(&mut *writer, &t.host)?;
            writer.write_all(b",\"port\":")?;
            serde_json::to_writer(&mut *writer, &t.port)?;
            writer.write_all(b",\"raw_input\":")?;
            serde_json::to_writer(&mut *writer, &t.raw_input)?;
            writer.write_all(b"}")?;
        }
        writer.write_all(b"],\"options\":{\"tcp_timeout_ms\":")?;
        serde_json::to_writer(&mut *writer, &req.options.tcp_timeout_ms)?;
        writer.write_all(b",\"concurrency\":")?;
        serde_json::to_writer(&mut *writer, &req.options.concurrency)?;
        writer.write_all(b",\"selected_features\":[")?;
        for (i, f) in req.options.selected_features.iter().enumerate() {
            if i > 0 {
                writer.write_all(b",")?;
            }
            serde_json::to_writer(&mut *writer, f.as_str())?;
        }
        writer.write_all(b"]},\"max_result_bytes\":")?;
        serde_json::to_writer(&mut *writer, &req.max_result_bytes)?;
        writer.write_all(b"}")?;

        // plan
        let plan = snapshot.plan();
        writer.write_all(b",\"plan\":{\"targets\":[")?;
        for (i, pt) in plan.targets.iter().enumerate() {
            if i > 0 {
                writer.write_all(b",")?;
            }
            writer.write_all(b"{\"target\":{\"host\":")?;
            serde_json::to_writer(&mut *writer, &pt.target.host)?;
            writer.write_all(b",\"port\":")?;
            serde_json::to_writer(&mut *writer, &pt.target.port)?;
            writer.write_all(b",\"raw_input\":")?;
            serde_json::to_writer(&mut *writer, &pt.target.raw_input)?;
            writer.write_all(b"},\"features\":[")?;
            for (fi, f) in pt.features.iter().enumerate() {
                if fi > 0 {
                    writer.write_all(b",")?;
                }
                serde_json::to_writer(&mut *writer, f.as_str())?;
            }
            writer.write_all(b"],\"requires_resolution\":")?;
            serde_json::to_writer(&mut *writer, &pt.requires_resolution)?;
            writer.write_all(b"}")?;
        }
        writer.write_all(b"],\"tcp_timeout_ms\":")?;
        serde_json::to_writer(&mut *writer, &plan.tcp_timeout_ms)?;
        writer.write_all(b",\"icmp_timeout_ms\":")?;
        serde_json::to_writer(&mut *writer, &plan.icmp_timeout_ms)?;
        writer.write_all(b",\"concurrency\":")?;
        serde_json::to_writer(&mut *writer, &plan.concurrency)?;
        writer.write_all(b",\"limitations\":")?;
        serde_json::to_writer(&mut *writer, &plan.limitations)?;
        writer.write_all(b"}")?;
    } else {
        writer.write_all(
            b",\"context_origin\":\"not_provided\",\"run_id\":null,\"request\":null,\"plan\":null",
        )?;
    }

    // report
    match source {
        Some(Ok(report)) => {
            writer.write_all(b",\"report\":{\"cancelled\":")?;
            serde_json::to_writer(&mut *writer, &report.cancelled)?;
            writer.write_all(b",\"limit_reached\":")?;
            serde_json::to_writer(&mut *writer, &report.limit_reached)?;
            writer.write_all(b",\"omitted_results\":")?;
            serde_json::to_writer(&mut *writer, &report.omitted_results)?;
            writer.write_all(b",\"errors\":")?;
            serde_json::to_writer(&mut *writer, &report.errors)?;
            writer.write_all(b",\"invocations\":{\"tcp_connect\":")?;
            serde_json::to_writer(&mut *writer, &report.invocations.tcp_connect)?;
            writer.write_all(b",\"icmp_ping\":")?;
            serde_json::to_writer(&mut *writer, &report.invocations.icmp_ping)?;
            writer.write_all(b",\"local_network\":")?;
            serde_json::to_writer(&mut *writer, &report.invocations.local_network)?;
            writer.write_all(b",\"dns_lookup\":")?;
            serde_json::to_writer(&mut *writer, &report.invocations.dns_lookup)?;
            writer.write_all(b",\"icmp_traceroute\":")?;
            serde_json::to_writer(&mut *writer, &report.invocations.icmp_traceroute)?;
            writer.write_all(b"},\"max_active_targets\":")?;
            serde_json::to_writer(&mut *writer, &report.max_active_targets)?;
            writer.write_all(b",\"targets_started\":")?;
            serde_json::to_writer(&mut *writer, &report.targets_started)?;
            writer.write_all(b",\"targets_completed\":")?;
            serde_json::to_writer(&mut *writer, &report.targets_completed)?;
            writer.write_all(b",\"serialized_result_bytes\":")?;
            serde_json::to_writer(&mut *writer, &report.serialized_result_bytes)?;
            writer.write_all(b"}")?;

            writer.write_all(b",\"run_errors\":null")?;
            writer.write_all(b",\"retained_rows\":")?;
            serde_json::to_writer(&mut *writer, &report.results.len())?;
        }
        Some(Err(errors)) => {
            writer.write_all(b",\"report\":null")?;
            writer.write_all(b",\"run_errors\":")?;
            serde_json::to_writer(&mut *writer, errors)?;
            writer.write_all(b",\"retained_rows\":null")?;
        }
        None => {
            writer.write_all(b",\"report\":null,\"run_errors\":null,\"retained_rows\":null")?;
        }
    }

    // exported_result_indices
    writer.write_all(b",\"exported_result_indices\":")?;
    serde_json::to_writer(&mut *writer, selected_indices)?;

    // cell_encoding
    writer.write_all(
        b",\"cell_encoding\":\"all_csv_data_cells_prefixed_one_apostrophe_then_rfc4180_quote\"}",
    )?;

    Ok(())
}

/// 진단 결과 및 실행 컨텍스트를 규격화된 TXT 바이트 페이로드로 인코딩합니다.
///
/// ## 규칙
/// - BOM 없음, CRLF 줄바꿈, 마지막 CRLF 포함.
/// - 정적 헤더 행 출력 후 `metadata=<compact JSON>` 행 출력.
/// - 보고서가 있고 선택된 행이 있는 경우 `result[원본인덱스]=<compact QuickResult JSON>` 행들 출력.
/// - `max_bytes`가 0이거나 작성 도중 한도를 초과하면 `ExportError::TooLarge` 반환 (부분 성공 0).
pub fn encode_txt(
    source: Option<&Result<QuickRunReport, Vec<String>>>,
    context: &ExportContext,
    filter: &ResultFilter,
    scope: ExportScope,
    max_bytes: usize,
) -> Result<Vec<u8>, ExportError> {
    if max_bytes == 0 {
        return Err(ExportError::TooLarge { limit: 0 });
    }

    let mut writer = BoundedWriter::new(max_bytes);

    // TXT 헤더
    writer
        .write_all("Network Quick Check 결과 (측정/추론/미확인 원문 보존)\r\n".as_bytes())
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;

    // 대상 행 인덱스 결정
    let (selected_indices, selected_results): (Vec<usize>, Vec<&QuickResult>) = match source {
        Some(Ok(report)) => match scope {
            ExportScope::All => (
                (0..report.results.len()).collect(),
                report.results.iter().collect(),
            ),
            ExportScope::Filtered => {
                let rows = select_rows(report, filter);
                let indices = rows.iter().map(|(idx, _)| *idx).collect();
                let results = rows.into_iter().map(|(_, res)| res).collect();
                (indices, results)
            }
        },
        _ => (Vec::new(), Vec::new()),
    };

    // metadata=<compact JSON>\r\n
    writer
        .write_all(b"metadata=")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    write_metadata_json(
        &mut writer,
        source,
        context,
        filter,
        scope,
        &selected_indices,
    )
    .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    writer
        .write_all(b"\r\n")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;

    // results
    for (idx, res) in selected_indices.iter().zip(selected_results.iter()) {
        let prefix = format!("result[{idx}]=");
        writer
            .write_all(prefix.as_bytes())
            .map_err(|e| io_err_to_export_err(e, max_bytes))?;
        serde_json::to_writer(&mut writer, res)
            .map_err(|e| io_err_to_export_err(e.into(), max_bytes))?;
        writer
            .write_all(b"\r\n")
            .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    }

    Ok(writer.into_inner())
}

/// 진단 결과 및 실행 컨텍스트를 규격화된 RFC 4180 호환 CSV 바이트 페이로드로 인코딩합니다.
///
/// ## 규칙
/// - BOM 없음, CRLF 줄바꿈, 마지막 CRLF 포함.
/// - 모든 레코드는 정확히 18개 셀로 구성됩니다.
/// - 헤더 행은 접두사 없이 큰따옴표로만 감싸집니다.
/// - 모든 데이터 행(메타데이터 행 및 결과 행)의 모든 데이터 셀은 선행 ASCII 작은따옴표(`'`) 접두사를
///   붙인 후 RFC 4180 큰따옴표 이스케이프가 적용됩니다.
/// - `max_bytes`가 0이거나 작성 도중 한도를 초과하면 `ExportError::TooLarge` 반환 (부분 성공 0).
pub fn encode_csv(
    source: Option<&Result<QuickRunReport, Vec<String>>>,
    context: &ExportContext,
    filter: &ResultFilter,
    scope: ExportScope,
    max_bytes: usize,
) -> Result<Vec<u8>, ExportError> {
    if max_bytes == 0 {
        return Err(ExportError::TooLarge { limit: 0 });
    }

    let mut writer = BoundedWriter::new(max_bytes);

    // 1. 헤더 행 작성 (quote만, 접두사 없음)
    for (i, &header) in CSV_HEADERS.iter().enumerate() {
        if i > 0 {
            writer
                .write_all(b",")
                .map_err(|e| io_err_to_export_err(e, max_bytes))?;
        }
        write_csv_header_cell(&mut writer, header)
            .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    }
    writer
        .write_all(b"\r\n")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;

    // 2. 선택 결과 행 인덱스 결정
    let (selected_indices, selected_results): (Vec<usize>, Vec<&QuickResult>) = match source {
        Some(Ok(report)) => match scope {
            ExportScope::All => (
                (0..report.results.len()).collect(),
                report.results.iter().collect(),
            ),
            ExportScope::Filtered => {
                let rows = select_rows(report, filter);
                let indices = rows.iter().map(|(idx, _)| *idx).collect();
                let results = rows.into_iter().map(|(_, res)| res).collect();
                (indices, results)
            }
        },
        _ => (Vec::new(), Vec::new()),
    };

    // 3. metadata JSON을 bounded 버퍼에 먼저 작성
    let remaining_budget = max_bytes.saturating_sub(writer.len());
    let mut meta_buf = BoundedWriter::new(remaining_budget);
    write_metadata_json(
        &mut meta_buf,
        source,
        context,
        filter,
        scope,
        &selected_indices,
    )
    .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    let meta_json_bytes = meta_buf.into_inner();
    let meta_json_str = std::str::from_utf8(&meta_json_bytes)
        .map_err(|e| ExportError::Serialization(e.to_string()))?;

    // 4. metadata 레코드 작성 (18셀)
    // col 0: "metadata", col 1..=15: "", col 16: meta_json_str, col 17: ""
    write_csv_data_cell(&mut writer, "metadata").map_err(|e| io_err_to_export_err(e, max_bytes))?;
    for _ in 1..=15 {
        writer
            .write_all(b",")
            .map_err(|e| io_err_to_export_err(e, max_bytes))?;
        write_csv_data_cell(&mut writer, "").map_err(|e| io_err_to_export_err(e, max_bytes))?;
    }
    writer
        .write_all(b",")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    write_csv_data_cell(&mut writer, meta_json_str)
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    writer
        .write_all(b",")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    write_csv_data_cell(&mut writer, "").map_err(|e| io_err_to_export_err(e, max_bytes))?;
    writer
        .write_all(b"\r\n")
        .map_err(|e| io_err_to_export_err(e, max_bytes))?;

    // 5. 결과 행들 작성 (source가 Ok인 경우에만)
    for (idx, res) in selected_indices.iter().zip(selected_results.iter()) {
        let idx_str = idx.to_string();
        let port_str = res.target_port.to_string();
        let elapsed_str = res
            .elapsed_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        let os_code_str = res
            .os_error_code
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());

        // details compact JSON 직렬화 (남은 예산 내 bounded)
        let rem_details = max_bytes.saturating_sub(writer.len());
        let mut details_buf = BoundedWriter::new(rem_details);
        serde_json::to_writer(&mut details_buf, &res.details)
            .map_err(|e| io_err_to_export_err(e.into(), max_bytes))?;
        let details_json_bytes = details_buf.into_inner();
        let details_json_str = std::str::from_utf8(&details_json_bytes)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        // raw_result compact JSON 직렬화 (남은 예산 내 bounded)
        let rem_raw = max_bytes.saturating_sub(writer.len());
        let mut raw_buf = BoundedWriter::new(rem_raw);
        serde_json::to_writer(&mut raw_buf, res)
            .map_err(|e| io_err_to_export_err(e.into(), max_bytes))?;
        let raw_json_bytes = raw_buf.into_inner();
        let raw_json_str = std::str::from_utf8(&raw_json_bytes)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        // 18개 셀 차례대로 작성
        let cells: [&str; 18] = [
            "result",
            &idx_str,
            &res.schema_version,
            &res.product,
            &res.session_id,
            res.timestamp_iso8601.as_deref().unwrap_or("null"),
            res.source_host.as_deref().unwrap_or("null"),
            &res.target_host,
            res.resolved_ip.as_deref().unwrap_or("null"),
            &port_str,
            res.feature.as_str(),
            res.status.as_str(),
            &elapsed_str,
            &os_code_str,
            details_json_str,
            res.evidence_level.as_str(),
            "",
            raw_json_str,
        ];

        for (col_idx, &cell_val) in cells.iter().enumerate() {
            if col_idx > 0 {
                writer
                    .write_all(b",")
                    .map_err(|e| io_err_to_export_err(e, max_bytes))?;
            }
            write_csv_data_cell(&mut writer, cell_val)
                .map_err(|e| io_err_to_export_err(e, max_bytes))?;
        }
        writer
            .write_all(b"\r\n")
            .map_err(|e| io_err_to_export_err(e, max_bytes))?;
    }

    Ok(writer.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui_state::GuiState;
    use network_core::quick::{
        EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickFeature, QuickStatus,
    };
    use network_core::runner::ProbeCounts;

    /// 테스트 검증용 독립 RFC 4180 CSV 파서.
    ///
    /// 큰따옴표 이스케이프(`""`), 필드 내부 CRLF, 쉼표 구분자, CRLF 줄바꿈을 완벽히 해석합니다.
    fn parse_rfc4180_csv(data: &[u8]) -> Result<Vec<Vec<String>>, String> {
        // CSV 구분자는 ASCII 바이트로 해석하고, 셀은 완성된 뒤 엄격 UTF-8로 디코딩한다.
        // encoder의 helper를 호출하지 않는 별도 파서로 전송 표현을 검증한다.
        std::str::from_utf8(data).map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        let mut record = Vec::new();
        let mut field = Vec::new();
        let mut quoted = false;
        let mut after_quote = false;
        let mut started = false;
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            if quoted {
                if b == b'"' {
                    if data.get(i + 1) == Some(&b'"') {
                        field.push(b'"');
                        i += 2;
                        continue;
                    }
                    quoted = false;
                    after_quote = true;
                } else {
                    field.push(b);
                }
                i += 1;
                continue;
            }
            if b == b',' || b == b'\r' {
                if b == b'\r' && data.get(i + 1) != Some(&b'\n') {
                    return Err("레코드 경계는 CRLF여야 합니다.".to_string());
                }
                record.push(
                    String::from_utf8(std::mem::take(&mut field)).map_err(|e| e.to_string())?,
                );
                started = false;
                after_quote = false;
                if b == b'\r' {
                    records.push(std::mem::take(&mut record));
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if b == b'\n' || after_quote {
                return Err("CSV 셀 종료 뒤의 잘못된 문자입니다.".to_string());
            }
            if b == b'"' {
                if started {
                    return Err("인용되지 않은 셀 안의 큰따옴표입니다.".to_string());
                }
                quoted = true;
            } else {
                field.push(b);
            }
            started = true;
            i += 1;
        }
        if quoted || started || after_quote || !record.is_empty() || !field.is_empty() {
            return Err("미완성 셀 또는 마지막 CRLF 누락입니다.".to_string());
        }
        Ok(records)
    }

    /// 데이터 셀에서 선행 수식 보호 작은따옴표(') 접두사 정확히 1개를 제거하는 헬퍼.
    fn unprefix_data_cell(cell: &str) -> Result<&str, String> {
        cell.strip_prefix('\'')
            .ok_or_else(|| format!("데이터 셀이 작은따옴표 접두사로 시작하지 않습니다: '{cell}'"))
    }

    /// 풍부한 합성 fixture(rich synthetic fixture)를 생성하는 헬퍼.
    ///
    /// 한글, 이모지, 수식 문자, 선행 공백/탭/CRLF/따옴표/쉼표, nullable의 None/Some,
    /// 중복 오류, 누락 건수 등을 모두 포함합니다. (실제 측정 증거가 아님)
    fn make_rich_synthetic_fixture() -> QuickRunReport {
        let results = vec![
            QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: "gui-run-1".to_string(),
                timestamp_iso8601: Some("2026-10-26T12:34:56Z".to_string()),
                source_host: Some("client.office.corp".to_string()),
                target_host: "한글-서버.테스트.kr".to_string(),
                resolved_ip: Some("192.0.2.1".to_string()),
                target_port: 443,
                feature: QuickFeature::TcpConnect,
                status: QuickStatus::PASS,
                elapsed_ms: Some(42),
                os_error_code: None,
                details: serde_json::json!({
                    "outcome": "연결 성공 🚀 (한글과 이모지)",
                    "limitations": [
                        "첫 번째 제한: \r\n CRLF 개행 및 \"큰따옴표\" 포함",
                        "=SUM(A1:A10)", // 수식 주입 시도 문자열
                        "@cmd /c calc", // @ 기호 시작
                        "+12345",       // + 기호 시작
                        "-12345",       // - 기호 시작
                        "'leading_quote" // 선행 작은따옴표
                    ],
                    "raw_measurement": {
                        "nested": {
                            "text": "\t선행 탭, 쉼표, 그리고 \"따옴표\"",
                            "value": 100
                        }
                    }
                }),
                evidence_level: EvidenceLevel::OBSERVED,
            },
            QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: "gui-run-1".to_string(),
                timestamp_iso8601: None,               // null 검증
                source_host: Some("null".to_string()), // 문자열 "null"과 실제 null 구분 검증
                target_host: "::1".to_string(),
                resolved_ip: None, // null 검증
                target_port: 8080,
                feature: QuickFeature::IcmpPing,
                status: QuickStatus::FAIL,
                elapsed_ms: None,           // null 검증
                os_error_code: Some(10061), // Windows WSAECONNREFUSED
                details: serde_json::json!({
                    "outcome": "REFUSED",
                    "limitations": [],
                    "raw_measurement": {}
                }),
                evidence_level: EvidenceLevel::OBSERVED,
            },
            QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: "gui-run-1".to_string(),
                timestamp_iso8601: Some("2026-10-26T12:35:00Z".to_string()),
                source_host: None,
                target_host: "unknown-host.local".to_string(),
                resolved_ip: None,
                target_port: 53,
                feature: QuickFeature::DnsLookup,
                status: QuickStatus::UNKNOWN,
                elapsed_ms: None,
                os_error_code: None,
                details: serde_json::json!({
                    "outcome": "UNKNOWN",
                    "limitations": ["해석 불가"],
                    "raw_measurement": {}
                }),
                evidence_level: EvidenceLevel::UNKNOWN,
            },
        ];

        QuickRunReport {
            results,
            cancelled: true,
            limit_reached: true,
            omitted_results: 15,
            errors: vec![
                "중복된 오류 1\r\n라인 개행 포함".to_string(),
                "중복된 오류 1\r\n라인 개행 포함".to_string(),
                "특수문자: \"따옴표\", 쉼표, '작은따옴표', =수식".to_string(),
            ],
            invocations: ProbeCounts {
                tcp_connect: 12,
                icmp_ping: 8,
                local_network: 2,
                dns_lookup: 5,
                icmp_traceroute: 1,
            },
            max_active_targets: 4,
            targets_started: 10,
            targets_completed: 8,
            serialized_result_bytes: 8192,
        }
    }

    #[test]
    fn test_txt_export_roundtrip_and_structure() {
        let report = make_rich_synthetic_fixture();
        let ok_source = Ok(report.clone());

        // 진짜 GuiState::begin_run을 통해 RunSnapshot 생성
        let mut state = GuiState::new();
        state
            .replace_targets("127.0.0.1:80\nexample.com:443")
            .unwrap();
        let snapshot = state.begin_run().unwrap();

        // Running/Cancelling에서는 편집하지 않는다. 같은 ID의 완료를 먼저 반영한 뒤
        // 편집 가능한 현재 draft를 바꾸어도 별도로 보관한 실행 snapshot은 불변이다.
        state
            .finish_run(snapshot.run_id(), ok_source.clone())
            .unwrap();
        state.replace_targets("other.com:8080").unwrap();
        state
            .set_options(network_core::targets::QuickOptions {
                tcp_timeout_ms: 777,
                concurrency: 1,
                selected_features: vec![QuickFeature::DnsLookup],
            })
            .unwrap();

        let context = ExportContext {
            snapshot: Some(&snapshot),
            program_version: "2.5.0-test",
        };

        let filter = ResultFilter {
            status: Some(QuickStatus::PASS),
            ..Default::default()
        };

        // 1. Filtered 스코프로 TXT 인코딩
        let txt_bytes = encode_txt(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::Filtered,
            1_000_000,
        )
        .expect("인코딩 성공");

        let txt_str = String::from_utf8(txt_bytes).expect("유효한 UTF-8이어야 함");

        // CRLF 개행 및 마지막 CRLF 확인
        assert!(txt_str.ends_with("\r\n"));
        let lines: Vec<&str> = txt_str.split("\r\n").collect();
        // 마지막 split 요소는 빈 문자열
        assert_eq!(lines.last(), Some(&""));

        // 헤더 행 확인
        assert_eq!(
            lines[0],
            "Network Quick Check 결과 (측정/추론/미확인 원문 보존)"
        );

        // metadata 행 확인
        assert!(lines[1].starts_with("metadata="));
        let meta_json = &lines[1]["metadata=".len()..];
        let meta_val: serde_json::Value =
            serde_json::from_str(meta_json).expect("metadata는 유효한 JSON이어야 함");

        assert_eq!(meta_val["format"], "network-quick-check-export-v1");
        assert_eq!(meta_val["program_version"], "2.5.0-test");
        assert_eq!(meta_val["source_state"], "report");
        assert_eq!(meta_val["export_scope"], "filtered");
        assert_eq!(meta_val["context_origin"], "supplied_run_snapshot");
        assert_eq!(meta_val["run_id"], snapshot.run_id().as_u64());
        assert_eq!(meta_val["retained_rows"], 3);
        assert_eq!(meta_val["exported_result_indices"], serde_json::json!([0]));

        // request & plan 스냅샷 불변 확인 (draft 변경의 영향 0)
        assert_eq!(meta_val["request"]["targets"].as_array().unwrap().len(), 2);
        assert_eq!(
            meta_val["request"]["targets"][0]["raw_input"],
            "127.0.0.1:80"
        );

        // Filtered이므로 PASS 결과인 result[0]만 있어야 함
        assert!(lines[2].starts_with("result[0]="));
        let result_json = &lines[2]["result[0]=".len()..];
        let restored_result: QuickResult =
            serde_json::from_str(result_json).expect("QuickResult 역직렬화 성공");
        assert_eq!(restored_result, report.results[0]);

        // result[1]이나 result[2]는 없어야 함
        assert_eq!(lines.len(), 4); // [헤더, metadata, result[0], ""]
    }

    #[test]
    fn test_csv_export_rfc4180_roundtrip_and_cell_unprefixing() {
        let report = make_rich_synthetic_fixture();
        let ok_source = Ok(report.clone());

        let mut state = GuiState::new();
        state.replace_targets("127.0.0.1:80").unwrap();
        let snapshot = state.begin_run().unwrap();

        let context = ExportContext {
            snapshot: Some(&snapshot),
            program_version: "2.5.0-test",
        };

        let filter = ResultFilter::default();

        // 1. All 스코프로 CSV 인코딩
        let csv_bytes = encode_csv(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::All,
            1_000_000,
        )
        .expect("CSV 인코딩 성공");

        // 2. 독립 RFC 4180 파서로 파싱
        let records = parse_rfc4180_csv(&csv_bytes).expect("CSV 파싱 성공");

        // 헤더 1 + 메타데이터 1 + 결과 3 = 5 레코드
        assert_eq!(records.len(), 5);

        // 3. 헤더 레코드 검증 (정확히 18개 열, 접두사 없음)
        assert_eq!(records[0].len(), 18);
        for (i, &expected_header) in CSV_HEADERS.iter().enumerate() {
            assert_eq!(records[0][i], expected_header);
        }

        // 4. 메타데이터 레코드 검증 (정확히 18개 열, 모든 데이터 셀 작은따옴표 접두사 제거)
        assert_eq!(records[1].len(), 18);
        assert_eq!(unprefix_data_cell(&records[1][0]).unwrap(), "metadata");
        for (col, cell) in records[1].iter().enumerate().take(16).skip(1) {
            assert_eq!(
                unprefix_data_cell(cell).unwrap(),
                "",
                "열 {col}은 빈 셀이어야 합니다."
            );
        }
        let meta_json_unprefixed = unprefix_data_cell(&records[1][16]).unwrap();
        let meta_val: serde_json::Value =
            serde_json::from_str(meta_json_unprefixed).expect("메타데이터 JSON 파싱");
        assert_eq!(meta_val["format"], "network-quick-check-export-v1");
        assert_eq!(meta_val["export_scope"], "all");
        assert_eq!(
            meta_val["exported_result_indices"],
            serde_json::json!([0, 1, 2])
        );
        assert_eq!(unprefix_data_cell(&records[1][17]).unwrap(), "");

        // 5. 결과 레코드들 검증 (정확히 18개 열, raw_result_json 완전 복원 일치)
        for row_idx in 0..3 {
            let record = &records[2 + row_idx];
            assert_eq!(record.len(), 18);
            assert_eq!(unprefix_data_cell(&record[0]).unwrap(), "result");
            assert_eq!(unprefix_data_cell(&record[1]).unwrap(), row_idx.to_string());

            // schema_version, product, session_id
            assert_eq!(
                unprefix_data_cell(&record[2]).unwrap(),
                QUICK_SCHEMA_VERSION
            );
            assert_eq!(unprefix_data_cell(&record[3]).unwrap(), QUICK_PRODUCT_NAME);
            assert_eq!(unprefix_data_cell(&record[4]).unwrap(), "gui-run-1");

            // raw_result_json 복원하여 원본 QuickResult와 완전 일치 검증
            let raw_json_unprefixed = unprefix_data_cell(&record[17]).unwrap();
            let restored: QuickResult =
                serde_json::from_str(raw_json_unprefixed).expect("raw_result JSON 파싱 성공");
            assert_eq!(
                restored, report.results[row_idx],
                "행 {row_idx}의 복원된 QuickResult가 원본과 일치해야 합니다."
            );
        }
    }

    #[test]
    fn test_budget_enforcement_exact_l_and_failures() {
        let report = make_rich_synthetic_fixture();
        let ok_source = Ok(report);

        let context = ExportContext {
            snapshot: None, // snapshot 미제공 시 테스트
            program_version: "1.0.0",
        };
        let filter = ResultFilter::default();

        // 1. TXT에 대한 정확한 한도 L 측정
        let full_txt = encode_txt(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::All,
            1_000_000,
        )
        .unwrap();
        let l_txt = full_txt.len();

        // limit = 0 -> 실패
        assert_eq!(
            encode_txt(Some(&ok_source), &context, &filter, ExportScope::All, 0),
            Err(ExportError::TooLarge { limit: 0 })
        );

        // limit = L - 1 -> 실패
        assert_eq!(
            encode_txt(
                Some(&ok_source),
                &context,
                &filter,
                ExportScope::All,
                l_txt - 1
            ),
            Err(ExportError::TooLarge { limit: l_txt - 1 })
        );

        // limit = L -> 정확히 성공
        let res_l = encode_txt(Some(&ok_source), &context, &filter, ExportScope::All, l_txt)
            .expect("L에서 성공해야 함");
        assert_eq!(res_l.len(), l_txt);

        // limit = L + 1 -> 성공
        let res_l_plus = encode_txt(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::All,
            l_txt + 1,
        )
        .expect("L+1에서 성공해야 함");
        assert_eq!(res_l_plus.len(), l_txt);

        // 2. CSV에 대한 정확한 한도 L 측정
        let full_csv = encode_csv(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::All,
            1_000_000,
        )
        .unwrap();
        let l_csv = full_csv.len();

        // limit = 0 -> 실패
        assert_eq!(
            encode_csv(Some(&ok_source), &context, &filter, ExportScope::All, 0),
            Err(ExportError::TooLarge { limit: 0 })
        );

        // limit = L - 1 -> 실패
        assert_eq!(
            encode_csv(
                Some(&ok_source),
                &context,
                &filter,
                ExportScope::All,
                l_csv - 1
            ),
            Err(ExportError::TooLarge { limit: l_csv - 1 })
        );

        // limit = L -> 정확히 성공
        let res_csv_l = encode_csv(Some(&ok_source), &context, &filter, ExportScope::All, l_csv)
            .expect("L에서 성공해야 함");
        assert_eq!(res_csv_l.len(), l_csv);

        // limit = L + 1 -> 성공
        let res_csv_l_plus = encode_csv(
            Some(&ok_source),
            &context,
            &filter,
            ExportScope::All,
            l_csv + 1,
        )
        .expect("L+1에서 성공해야 함");
        assert_eq!(res_csv_l_plus.len(), l_csv);

        // 오류 발생 후 원본 source 및 context 불변, 다시 호출 시 성공 확인
        let retry_txt =
            encode_txt(Some(&ok_source), &context, &filter, ExportScope::All, l_txt).unwrap();
        assert_eq!(retry_txt, full_txt);
    }

    // 부모 QA 보강: 아래 값은 인코딩/보존용 합성 DTO이며 실제 네트워크 측정이 아니다.
    fn parent_expected_metadata(
        source: Option<&Result<QuickRunReport, Vec<String>>>,
        context: &ExportContext,
        filter: &ResultFilter,
        scope: ExportScope,
        indices: &[usize],
    ) -> serde_json::Value {
        use serde_json::json;
        let (run_id, request, plan) = if let Some(s) = context.snapshot {
            let r = s.request();
            let p = s.plan();
            let targets = r
                .targets
                .iter()
                .map(|t| json!({"host":t.host,"port":t.port,"raw_input":t.raw_input}))
                .collect::<Vec<_>>();
            let planned = p.targets.iter().map(|t| json!({
                "target":{"host":t.target.host,"port":t.target.port,"raw_input":t.target.raw_input},
                "features":t.features.iter().map(|f| f.as_str()).collect::<Vec<_>>(),"requires_resolution":t.requires_resolution
            })).collect::<Vec<_>>();
            (
                json!(s.run_id().as_u64()),
                json!({
                    "session_id":r.session_id,"timestamp_iso8601":r.timestamp_iso8601,"source_host":r.source_host,
                    "targets":targets,"options":{"tcp_timeout_ms":r.options.tcp_timeout_ms,"concurrency":r.options.concurrency,
                    "selected_features":r.options.selected_features.iter().map(|f|f.as_str()).collect::<Vec<_>>()},"max_result_bytes":r.max_result_bytes
                }),
                json!({"targets":planned,"tcp_timeout_ms":p.tcp_timeout_ms,"icmp_timeout_ms":p.icmp_timeout_ms,
                "concurrency":p.concurrency,"limitations":p.limitations}),
            )
        } else {
            (json!(null), json!(null), json!(null))
        };
        let (state, report, errors, retained) = match source {
            None => ("not_run", json!(null), json!(null), json!(null)),
            Some(Err(e)) => ("run_errors", json!(null), json!(e), json!(null)),
            Some(Ok(r)) => {
                // 실제 Core Serialize에서 results만 제거한 독립 expected 값과 전체 비교한다.
                let mut meta = serde_json::to_value(r).unwrap();
                assert!(meta.as_object_mut().unwrap().remove("results").is_some());
                ("report", meta, json!(null), json!(r.results.len()))
            }
        };
        json!({"format":"network-quick-check-export-v1","program_version":context.program_version,
            "source_state":state,"export_scope":match scope {ExportScope::All=>"all",ExportScope::Filtered=>"filtered"},
            "filter":{"status":filter.status.map(|s|s.as_str()),"feature":filter.feature.map(|f|f.as_str()),
                "evidence_level":filter.evidence_level.map(|e|e.as_str()),"target_query":filter.target_query},
            "context_origin":if context.snapshot.is_some(){"supplied_run_snapshot"}else{"not_provided"},
            "run_id":run_id,"request":request,"plan":plan,"report":report,"run_errors":errors,
            "retained_rows":retained,"exported_result_indices":indices,
            "cell_encoding":"all_csv_data_cells_prefixed_one_apostrophe_then_rfc4180_quote"})
    }

    fn parent_assert_all_csv_cells(
        records: &[Vec<String>],
        source: Option<&Result<QuickRunReport, Vec<String>>>,
        expected_meta: &serde_json::Value,
        indices: &[usize],
    ) {
        assert_eq!(records.len(), 2 + indices.len());
        assert_eq!(records[0], CSV_HEADERS);
        for record in &records[1..] {
            assert_eq!(record.len(), 18);
            for cell in record {
                assert!(cell.starts_with('\''));
            }
        }
        let metadata = records[1]
            .iter()
            .map(|c| unprefix_data_cell(c).unwrap())
            .collect::<Vec<_>>();
        for (i, cell) in metadata.iter().enumerate() {
            match i {
                0 => assert_eq!(*cell, "metadata"),
                16 => assert_eq!(
                    serde_json::from_str::<serde_json::Value>(cell).unwrap(),
                    *expected_meta
                ),
                _ => assert_eq!(*cell, ""),
            }
        }
        for (pos, index) in indices.iter().copied().enumerate() {
            let r = &source.unwrap().as_ref().unwrap().results[index];
            let cells = records[pos + 2]
                .iter()
                .map(|c| unprefix_data_cell(c).unwrap())
                .collect::<Vec<_>>();
            let expected = vec![
                "result".to_string(),
                index.to_string(),
                r.schema_version.clone(),
                r.product.clone(),
                r.session_id.clone(),
                r.timestamp_iso8601.clone().unwrap_or("null".into()),
                r.source_host.clone().unwrap_or("null".into()),
                r.target_host.clone(),
                r.resolved_ip.clone().unwrap_or("null".into()),
                r.target_port.to_string(),
                r.feature.as_str().into(),
                r.status.as_str().into(),
                r.elapsed_ms.map(|n| n.to_string()).unwrap_or("null".into()),
                r.os_error_code
                    .map(|n| n.to_string())
                    .unwrap_or("null".into()),
            ];
            for i in 0..14 {
                assert_eq!(cells[i], expected[i], "row {index} column {i}");
            }
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(cells[14]).unwrap(),
                r.details
            );
            assert_eq!(cells[15], r.evidence_level.as_str());
            assert_eq!(cells[16], "");
            // 보존/보안 fixture는 상위 validator를 일부러 통과하지 않는 문자열도 포함한다.
            // Core의 엄격 Deserialize를 완화하지 않고 JSON 값 전체로 비교한다.
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(cells[17]).unwrap(),
                serde_json::to_value(r).unwrap()
            );
        }
    }

    /// 파싱한 값과 별개로 각 셀의 바깥 큰따옴표가 실제 wire에 있는지 검사한다.
    fn parent_quote_all_wire(data: &[u8]) -> Result<Vec<usize>, &'static str> {
        let mut i = 0;
        let mut widths = Vec::new();
        let mut columns = 0;
        while i < data.len() {
            if data[i] != b'"' {
                return Err("모든 셀은 인용되어야 합니다.");
            }
            i += 1;
            loop {
                let Some(&b) = data.get(i) else {
                    return Err("미종료 셀");
                };
                i += 1;
                if b != b'"' {
                    continue;
                }
                if data.get(i) == Some(&b'"') {
                    i += 1;
                    continue;
                }
                break;
            }
            columns += 1;
            match data.get(i) {
                Some(b',') => {
                    i += 1;
                }
                Some(b'\r') if data.get(i + 1) == Some(&b'\n') => {
                    i += 2;
                    widths.push(columns);
                    columns = 0;
                }
                _ => return Err("셀 뒤의 구분자 또는 최종 CRLF 누락"),
            }
        }
        if columns != 0 || widths.is_empty() {
            return Err("미완료 레코드");
        }
        Ok(widths)
    }

    #[test]
    fn parent_quote_all_wire_rejects_value_equivalent_unquoted_mutations() {
        let source = Ok(make_rich_synthetic_fixture());
        let context = ExportContext {
            snapshot: None,
            program_version: "test",
        };
        let csv = encode_csv(
            Some(&source),
            &context,
            &ResultFilter::default(),
            ExportScope::All,
            1_000_000,
        )
        .unwrap();
        assert_eq!(parent_quote_all_wire(&csv).unwrap(), vec![18; 5]);
        let original = parse_rfc4180_csv(&csv).unwrap();
        for quoted in [
            b"\"record_type\"".as_slice(),
            b"\"'metadata\"",
            b"\"'result\"",
            b"\"'0\"",
        ] {
            let start = csv.windows(quoted.len()).position(|v| v == quoted).unwrap();
            let mut mutated = csv[..start].to_vec();
            mutated.extend_from_slice(&quoted[1..quoted.len() - 1]);
            mutated.extend_from_slice(&csv[start + quoted.len()..]);
            // 일반 RFC 파서는 같은 값으로 복원하지만 이 제품의 quote-all 계약은 거부한다.
            assert_eq!(parse_rfc4180_csv(&mutated).unwrap(), original);
            assert!(parent_quote_all_wire(&mutated).is_err());
        }
    }

    #[test]
    fn parent_csv_parser_strict_utf8_quote_and_crlf_controls() {
        assert_eq!(
            parse_rfc4180_csv("\"한글🚀\r\n쉼표,\"\"값\"\"\",\"\"\r\n".as_bytes()).unwrap(),
            vec![vec!["한글🚀\r\n쉼표,\"값\"".to_string(), "".to_string()]]
        );
        for bad in [
            b"\"\xff\"\r\n".as_slice(),
            b"\"unterminated\r\n",
            b"\"a\"junk\r\n",
            b"a\"b\r\n",
            b"\"a\"\n",
            b"a\rb",
            b"\"a\"",
        ] {
            assert!(parse_rfc4180_csv(bad).is_err(), "invalid bytes: {bad:?}");
        }
    }

    #[test]
    fn parent_whole_metadata_all_cells_scopes_and_originals_preserved() {
        let mut state = GuiState::new();
        state
            .replace_targets("127.0.0.1:080\n[::1]:443\nexample.com:443")
            .unwrap();
        state
            .set_options(network_core::targets::QuickOptions {
                tcp_timeout_ms: 1234,
                concurrency: 2,
                selected_features: vec![
                    QuickFeature::TcpConnect,
                    QuickFeature::DnsLookup,
                    QuickFeature::IcmpPing,
                ],
            })
            .unwrap();
        let snapshot = state.begin_run().unwrap();
        let snapshot_before = snapshot.clone();
        let mut report = make_rich_synthetic_fixture();
        report.results.push(report.results[0].clone()); // 非연속 중복은 원인덱스 0,3이다.
        let source = Ok(report);
        // Running/Cancelling 편집 거부는 유지하며, 완료 이후에만 draft를 바꾼다.
        let running = state.clone();
        assert!(state.replace_targets("other.com:9").is_err());
        assert_eq!(state, running);
        state.request_cancel();
        let cancelling = state.clone();
        assert!(state.set_options(Default::default()).is_err());
        assert_eq!(state, cancelling);
        state.finish_run(snapshot.run_id(), source.clone()).unwrap();
        assert!(state.active_snapshot().is_none());
        state.replace_targets("other.com:9").unwrap();
        state
            .set_options(network_core::targets::QuickOptions {
                tcp_timeout_ms: 777,
                concurrency: 1,
                selected_features: vec![QuickFeature::LocalNetwork],
            })
            .unwrap();
        let context = ExportContext {
            snapshot: Some(&snapshot),
            program_version: "=한글🚀\r\nversion,\"x\"",
        };
        let filter = ResultFilter {
            status: Some(QuickStatus::PASS),
            ..Default::default()
        };
        let before = source.clone();
        let filter_before = filter.clone();
        for scope in [ExportScope::All, ExportScope::Filtered] {
            let indices: Vec<usize> = if scope == ExportScope::All {
                vec![0, 1, 2, 3]
            } else {
                vec![0, 3]
            };
            for cancelled in [false, true] {
                let mut variant = source.clone();
                variant.as_mut().unwrap().cancelled = cancelled;
                let expected =
                    parent_expected_metadata(Some(&variant), &context, &filter, scope, &indices);
                let txt = encode_txt(Some(&variant), &context, &filter, scope, 1_000_000).unwrap();
                assert!(!txt.starts_with(&[0xef, 0xbb, 0xbf]));
                assert!(txt.ends_with(b"\r\n"));
                let lines = std::str::from_utf8(&txt)
                    .unwrap()
                    .split("\r\n")
                    .collect::<Vec<_>>();
                assert_eq!(lines.len(), 3 + indices.len());
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(
                        lines[1].strip_prefix("metadata=").unwrap()
                    )
                    .unwrap(),
                    expected
                );
                for (pos, index) in indices.iter().enumerate() {
                    let prefix = format!("result[{index}]=");
                    assert_eq!(
                        serde_json::from_str::<QuickResult>(
                            lines[pos + 2].strip_prefix(&prefix).unwrap()
                        )
                        .unwrap(),
                        variant.as_ref().unwrap().results[*index]
                    );
                }
                let csv = encode_csv(Some(&variant), &context, &filter, scope, 1_000_000).unwrap();
                assert!(!csv.starts_with(&[0xef, 0xbb, 0xbf]));
                parent_assert_all_csv_cells(
                    &parse_rfc4180_csv(&csv).unwrap(),
                    Some(&variant),
                    &expected,
                    &indices,
                );
            }
        }
        assert_eq!(source, before);
        assert_eq!(filter, filter_before);
        assert_eq!(snapshot, snapshot_before);
    }

    #[test]
    fn parent_every_text_cell_formula_prefix_and_original_apostrophe_survive() {
        for danger in [
            "=1+1",
            "+cmd",
            "-2",
            "@cmd",
            "'원문",
            " =1",
            "\t=1",
            "\r\n=1",
            "한글🚀,\"quote\"\r\n끝",
            "",
        ] {
            let mut report = make_rich_synthetic_fixture();
            report.results.truncate(1);
            let r = &mut report.results[0];
            // 상위 validator의 유효 입력이 아니라 모든 공개 인코더 필드의 보안 보존 fixture다.
            r.schema_version = danger.into();
            r.product = danger.into();
            r.session_id = danger.into();
            r.timestamp_iso8601 = Some(danger.into());
            r.source_host = Some(danger.into());
            r.target_host = danger.into();
            r.resolved_ip = Some(danger.into());
            r.details = serde_json::json!({"raw":danger,"array":[null,"null",danger]});
            report.errors = vec![danger.into(), danger.into()];
            let source = Ok(report);
            let context = ExportContext {
                snapshot: None,
                program_version: danger,
            };
            let filter = ResultFilter {
                target_query: danger.into(),
                ..Default::default()
            };
            let expected =
                parent_expected_metadata(Some(&source), &context, &filter, ExportScope::All, &[0]);
            let bytes = encode_csv(
                Some(&source),
                &context,
                &filter,
                ExportScope::All,
                1_000_000,
            )
            .unwrap();
            parent_assert_all_csv_cells(
                &parse_rfc4180_csv(&bytes).unwrap(),
                Some(&source),
                &expected,
                &[0],
            );
        }
    }

    #[test]
    fn parent_missing_empty_and_filtered_zero_have_exact_explicit_null_metadata() {
        let context = ExportContext {
            snapshot: None,
            program_version: "test",
        };
        let filter = ResultFilter {
            target_query: "no matching row".into(),
            ..Default::default()
        };
        let errors = Err(vec!["=한글\r\nerror🚀".into(), "=한글\r\nerror🚀".into()]);
        let mut empty = make_rich_synthetic_fixture();
        empty.results.clear();
        let empty = Ok(empty);
        let full = Ok(make_rich_synthetic_fixture());
        for source in [None, Some(&errors), Some(&empty), Some(&full)] {
            let expected =
                parent_expected_metadata(source, &context, &filter, ExportScope::Filtered, &[]);
            let csv =
                encode_csv(source, &context, &filter, ExportScope::Filtered, 1_000_000).unwrap();
            parent_assert_all_csv_cells(&parse_rfc4180_csv(&csv).unwrap(), source, &expected, &[]);
            let txt =
                encode_txt(source, &context, &filter, ExportScope::Filtered, 1_000_000).unwrap();
            let text = String::from_utf8(txt).unwrap();
            let value = serde_json::from_str::<serde_json::Value>(
                text.split("\r\n")
                    .nth(1)
                    .unwrap()
                    .strip_prefix("metadata=")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(value, expected);
            for key in ["run_id", "request", "plan"] {
                assert!(value.as_object().unwrap().contains_key(key));
                assert_eq!(value.get(key), Some(&serde_json::Value::Null));
            }
        }
    }

    #[test]
    fn parent_budget_exhausted_inside_each_json_string_is_too_large() {
        let huge = "\"한글🚀\r\n".repeat(20_000);
        let mut cases = Vec::new();
        for location in 0..6 {
            let mut report = make_rich_synthetic_fixture();
            let mut version = "test".to_string();
            let mut filter = ResultFilter::default();
            match location {
                0 => version = huge.clone(),
                1 => filter.target_query = huge.clone(),
                2 => report.errors = vec![huge.clone()],
                3 => report.results[0].details = serde_json::json!({"raw":huge}),
                4 => report.results[0].target_host = huge.clone(),
                _ => {}
            }
            let source = if location == 5 {
                Err(vec![huge.clone()])
            } else {
                Ok(report)
            };
            cases.push((source, version, filter));
        }
        for (source, version, filter) in cases {
            let context = ExportContext {
                snapshot: None,
                program_version: &version,
            };
            let before = source.clone();
            for limit in [128, 512, 2048] {
                for actual in [
                    encode_txt(Some(&source), &context, &filter, ExportScope::All, limit),
                    encode_csv(Some(&source), &context, &filter, ExportScope::All, limit),
                ] {
                    assert_eq!(actual, Err(ExportError::TooLarge { limit }));
                }
            }
            assert_eq!(source, before);
            for bytes in [
                encode_txt(
                    Some(&source),
                    &context,
                    &filter,
                    ExportScope::All,
                    8_000_000,
                )
                .unwrap(),
                encode_csv(
                    Some(&source),
                    &context,
                    &filter,
                    ExportScope::All,
                    8_000_000,
                )
                .unwrap(),
            ] {
                assert!(bytes.ends_with(b"\r\n"));
            }
        }
    }

    #[test]
    fn test_not_run_and_run_errors_sources() {
        let context = ExportContext {
            snapshot: None,
            program_version: "1.0.0",
        };
        let filter = ResultFilter::default();

        // 1. None 소스 (not_run)
        let txt_none = encode_txt(None, &context, &filter, ExportScope::All, 10_000).unwrap();
        let txt_none_str = String::from_utf8(txt_none).unwrap();
        let lines_none: Vec<&str> = txt_none_str.split("\r\n").collect();
        // 헤더, metadata, 빈 줄 (총 3개 요소)
        assert_eq!(lines_none.len(), 3);
        assert!(lines_none[1].starts_with("metadata="));
        let meta_none: serde_json::Value =
            serde_json::from_str(&lines_none[1]["metadata=".len()..]).unwrap();
        assert_eq!(meta_none["source_state"], "not_run");
        assert_eq!(meta_none["context_origin"], "not_provided");
        assert!(meta_none["run_id"].is_null());
        assert!(meta_none["request"].is_null());
        assert!(meta_none["plan"].is_null());
        assert!(meta_none["report"].is_null());
        assert!(meta_none["run_errors"].is_null());
        assert!(meta_none["retained_rows"].is_null());
        assert_eq!(meta_none["exported_result_indices"], serde_json::json!([]));

        // CSV None 소스
        let csv_none = encode_csv(None, &context, &filter, ExportScope::All, 10_000).unwrap();
        let records_none = parse_rfc4180_csv(&csv_none).unwrap();
        // 헤더 1 + 메타데이터 1 = 2개 레코드
        assert_eq!(records_none.len(), 2);

        // 2. Err 소스 (run_errors)
        let err_list = vec![
            "진단 타임아웃 오류".to_string(),
            "네트워크 드라이버 오류".to_string(),
        ];
        let err_source = Err(err_list.clone());

        let txt_err = encode_txt(
            Some(&err_source),
            &context,
            &filter,
            ExportScope::All,
            10_000,
        )
        .unwrap();
        let txt_err_str = String::from_utf8(txt_err).unwrap();
        let lines_err: Vec<&str> = txt_err_str.split("\r\n").collect();
        assert_eq!(lines_err.len(), 3);
        let meta_err: serde_json::Value =
            serde_json::from_str(&lines_err[1]["metadata=".len()..]).unwrap();
        assert_eq!(meta_err["source_state"], "run_errors");
        assert_eq!(
            meta_err["run_errors"],
            serde_json::json!(["진단 타임아웃 오류", "네트워크 드라이버 오류"])
        );
        assert!(meta_err["report"].is_null());
        assert!(meta_err["retained_rows"].is_null());
        assert_eq!(meta_err["exported_result_indices"], serde_json::json!([]));

        // CSV Err 소스
        let csv_err = encode_csv(
            Some(&err_source),
            &context,
            &filter,
            ExportScope::All,
            10_000,
        )
        .unwrap();
        let records_err = parse_rfc4180_csv(&csv_err).unwrap();
        assert_eq!(records_err.len(), 2);
    }
}
