"""Label original design snapshots without executing document contents."""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1]
report=json.loads((R/'artifacts/g1-gate-report.json').read_text(encoding='utf-8'))
changed=[name for name,digest in report['source_sha256'].items()if hashlib.sha256((R/name).read_bytes()).hexdigest()!=digest]
assert not changed,changed
note='> **G0 설계 시점 문서**: 아래 표의 상태는 최초 설계 당시 기록이다. 현재 로컬 수용 판정은 G0 개발 범위/G1 오프라인 기반 통과이며, 최신 실제 수치·소스·미완료 범위는 `PROGRESS.md` 및 `artifacts/g1-gate-report.json`을 기준으로 한다. 전체 P0·실제 통신·설치·운영 완료를 의미하지 않는다.\n\n'
for name in ['gate-checklist.md','requirement-traceability.md','architecture.md']:
 p=R/'docs'/name;text=p.read_text(encoding='utf-8')
 if not text.startswith(note):p.write_text(note+text,encoding='utf-8',newline='\n')
print(json.dumps({'labelled_documents':3,'runtime_source_hashes_unchanged':len(report['source_sha256']),'network_requests':0}))
