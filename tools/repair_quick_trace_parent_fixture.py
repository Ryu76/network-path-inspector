"""Trace 전체시험에서 드러난 모의 파이프 모델 오류와 원시 오류코드 보존을 보정한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgtrace';manifest=json.loads((R/'artifacts/qg2c-trace-canonical-source.json').read_text(encoding='utf-8'));rel='crates/network-core/src/traceroute.rs';p=W/rel;assert hashlib.sha256(p.read_bytes()).hexdigest()==manifest['canonical_source_sha256'][rel];text=p.read_text(encoding='utf-8')
def change(old,new,count=1):
 global text
 assert text.count(old)==count,(old,text.count(old));text=text.replace(old,new)
change('Result<(), (u32, String)>','Result<(), (Option<i64>, String)>')
change('Result<bool, (u32, String)>','Result<bool, (Option<i64>, String)>')
change('Err((0, format!("파이프 읽기 오류: {e}")))','Err((e.raw_os_error().map(i64::from), format!("파이프 읽기 오류: {e}")))')
change('Err((0, format!("잔량 파이프 읽기 오류: {e}")))','Err((e.raw_os_error().map(i64::from), format!("잔량 파이프 읽기 오류: {e}")))')
change('PipeStatus::Error(code, msg) => Err((code, msg)),','PipeStatus::Error(code, msg) => Err((Some(i64::from(code)), msg)),')
change('PipeStatus::Error(code, msg) => return Err((code, msg)),','PipeStatus::Error(code, msg) => return Err((Some(i64::from(code)), msg)),')
# 성공/실패로부터 독립된 실제 코드 유무를 표시한다. 임의 0으로 채우지 않는다.
for label in ['표준 출력 파이프 오류','표준 에러 파이프 오류','표준 출력 잔량 수집 중 오류','표준 에러 잔량 수집 중 오류']:
 change('limitations.push(format!("'+label+' (코드 {code}): {msg}"));','limitations.push(format!("'+label+' (코드 {}): {msg}", code.map_or_else(|| "미확인".to_string(), |value| value.to_string())));')
change('        assert_eq!(code, 5);','        assert_eq!(code, Some(5));')
change('''        read_pos: usize,
        fail_read: bool,''','''        read_pos: usize,
        fail_read: bool,
        read_error_code: Option<i32>,''')
change('''                read_pos: 0,
                fail_read: false,''','''                read_pos: 0,
                fail_read: false,
                read_error_code: None,''')
change('''            if self.fail_read {
                return Err(std::io::Error::new(''','''            if self.fail_read {
                if let Some(code) = self.read_error_code {
                    return Err(std::io::Error::from_raw_os_error(code));
                }
                return Err(std::io::Error::new(''')
old='''        let overflow_data = vec![b'A'; 40000];
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(40000)], overflow_data);
        let mut buf = Vec::new();
        let mut truncated = false;
        let res = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated);
        assert!(res.is_ok());
        assert!(truncated);
        assert_eq!(buf.len(), 32768);'''
new='''        let overflow_data = vec![b'A'; 40000];
        // production 수집기는 한 번에 최대 4096바이트만 읽는다.
        // 실제 남은 가용량과 반복 수집을 모의하여 상한의 의미를 검증한다.
        let mut remaining = overflow_data.len();
        let mut availability = Vec::new();
        while remaining > 0 {
            availability.push(PipeStatus::Data(remaining));
            remaining -= remaining.min(4096);
        }
        availability.push(PipeStatus::Eof);
        let mut pipe = MockPipe::new(availability, overflow_data);
        let mut buf = Vec::new();
        let mut truncated = false;
        let drained = drain_pipe_limited(&mut pipe, &mut buf, 32768, &mut truncated, 16)
            .expect("모의 잔량 수집");
        assert!(drained);
        assert!(truncated);
        assert_eq!(buf.len(), 32768);
        assert_eq!(pipe.read_pos, 40000);''';change(old,new)
# source 안의 private helper 단위시험을 확장하되 native IO는 호출하지 않는다.
anchor='''    #[test]
    fn test_mock_pipe_overflow_truncated()'''
extra='''    #[test]
    fn test_mock_read_error_preserves_raw_code() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(1)], vec![1]);
        pipe.fail_read = true;
        pipe.read_error_code = Some(5);
        let mut buf = Vec::new();
        let mut truncated = false;
        let error = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated)
            .expect_err("합성 read 오류");
        assert_eq!(error.0, Some(5));
    }

    #[test]
    fn test_mock_read_error_without_raw_code_stays_unknown() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(1)], vec![1]);
        pipe.fail_read = true;
        let mut buf = Vec::new();
        let mut truncated = false;
        let error = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated)
            .expect_err("원시 코드 없는 합성 read 오류");
        assert_eq!(error.0, None);
    }

    #[test]
    fn test_mock_terminal_drain_preserves_available_tail() {
        let mut pipe = MockPipe::new(
            vec![PipeStatus::Data(4), PipeStatus::Eof], b"tail".to_vec());
        let mut buf = b"prefix".to_vec();
        let mut truncated = false;
        assert!(drain_pipe_limited(&mut pipe, &mut buf, 32768, &mut truncated, 4)
            .expect("합성 종료 후 잔량 수집"));
        assert_eq!(buf, b"prefixtail");
        assert!(!truncated);
    }

''';change(anchor,extra+anchor)
p.write_text(text,encoding='utf-8',newline='\n');q=subprocess.run(['cargo','fmt','-p','network-core'],cwd=W,capture_output=True,timeout=30);assert q.returncode==0,q.stderr
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'parent_scope':'전체시험8PASS1FAIL에서드러난모의fixture정정+실제read오류코드보존','failure_evidence':'artifacts/commands/qg2c-trace-canonical-all-tests.json','fixture_fix':'4096바이트 단일 chunk 함수를40000바이트모의입력으로한번호출하고32768바이트를기대한불량fixture. 실제가용량감소를모의한bounded drain으로교체;기대상한·절삭·전체소비단언은강화.','production_fix':'read오류를고정0으로채우지않고raw_os_error의Option값보존,Peek실제u32코드도i64로무손실보존. public API변경0.','extra_pure_regressions':3,'previous_canonical_sha256':manifest['canonical_source_sha256'],'canonical_source_sha256':{item:hashlib.sha256((W/item).read_bytes()).hexdigest()for item in manifest['canonical_source_sha256']},'accepted':False};out=R/'artifacts/qg2c-trace-parent-io-fixture-repair.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('Trace 모의fixture 의미정정·실제OS오류코드 Option보존·순수회귀3개 추가. 실행검증 전.')
