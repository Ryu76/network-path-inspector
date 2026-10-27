"""종료한 실행기 actor SHA를 검증하고 중복된 문법 블록만 최소 보정한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qg2runner';run=R/'.harness/runs/qg2continue-qg2runner';load=lambda p:json.loads(p.read_text(encoding='utf-8'))
audit=load(R/'artifacts/qg2continue-actor-policy-audit.json');assert next(a for a in audit['actors']if a['role']=='qg2runner')['passed'];result=load(run/'result.json');after=load(run/'after.json');source={rel:after[rel]for rel in result['changed_paths']}
for rel,sha in source.items():assert hashlib.sha256((w/rel).read_bytes()).hexdigest()==sha,rel
p=w/'crates/network-core/src/runner.rs';text=p.read_text(encoding='utf-8');old='''        }
            } else {
                break;
            }
        }

        if join_set.is_empty()''';assert text.count(old)==1;text=text.replace(old,'''        }

        if join_set.is_empty()''');p.write_text(text,encoding='utf-8',newline='\n')
canonical={}
for rel in source:
 q=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=w,input=(w/rel).read_bytes(),capture_output=True,timeout=20);assert q.returncode==0,q.stderr;canonical[rel]=q.stdout
q=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,timeout=30);assert q.returncode==0,q.stderr
for rel,expected in canonical.items():assert(w/rel).read_bytes()==expected
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'actor_stage':'qg2continue','actor_role':'qg2runner','actor_policy_passed':True,'parent_adjustment':'qg2b-style-first-tests exit101에서 확인한 중복 else/break/닫는괄호 4줄만 삭제. 나머지는 edition2024 rustfmt이며 동작 변경 없음.','actor_source_sha256':source,'canonical_source_sha256':{rel:hashlib.sha256((w/rel).read_bytes()).hexdigest()for rel in source},'accepted':False};record['parent_adjustment']='qg2b-style-first-tests exit101에서 확인한 중복 else/break/닫는괄호 4줄만 삭제. 나머지는 edition2024 rustfmt이며 동작 변경 없음.';out=R/'artifacts/qg2b-runner-style-canonical.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('실행기 actor2파일 SHA 확인. 중복 문법4줄 및 rustfmt만 부모 보정.')
