"""Independent real G2-A CLI checks against owned loopback peers only."""
import argparse,datetime,json,pathlib,socket,subprocess,tempfile,copy,time
R=pathlib.Path(__file__).resolve().parents[1];P=argparse.ArgumentParser();P.add_argument('--exe',type=pathlib.Path,required=True);args=P.parse_args();assert args.exe.is_file()
SCRATCH=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch');rows=[];raw={}
base=json.loads((R/'fixtures/g1/valid_profile_quick.json').read_text(encoding='utf-8'));base['limits']['retries']=0;base['limits']['tcp_timeout_ms']=5000;base['limits']['max_concurrent_tcp']=1;base['capture_approved']=False;base['mode']='standalone'
def cli(selected,host='127.0.0.1',port=443,expect=0):
 profile=copy.deepcopy(base);profile['selected_features']=selected;profile['target']={'host':host,'port':port,'protocol':'TCP'}
 with tempfile.TemporaryDirectory(prefix='npi-g2-cli-',dir=SCRATCH)as folder:
  path=pathlib.Path(folder)/'profile.json';path.write_text(json.dumps(profile),encoding='utf-8');p=subprocess.run([str(args.exe),str(path)],capture_output=True,encoding='utf-8',errors='replace',timeout=10)
 assert p.returncode==expect,('exit',p.returncode,p.stderr[:500]);return json.loads(p.stdout)
def row(out,fid):return next(x for x in out['feature_results']if x['feature_id']==fid)
def case(name,fn):
 started=time.monotonic()
 try:
  value=fn();raw[name]=value;rows.append({'name':name,'passed':True,'elapsed_ms':round((time.monotonic()-started)*1000)})
 except Exception as e:rows.append({'name':name,'passed':False,'error':str(e),'elapsed_ms':round((time.monotonic()-started)*1000)})
def empty():
 out=cli([]);assert len(out['feature_results'])==23;assert all(x['status']=='SKIPPED_BY_USER'and x['duration_ms']is None for x in out['feature_results']);assert set(out['collector_counts'].values())=={0};assert not out['measurements'];return out
def unsupported():
 out=cli(['packet_capture','tcp_traceroute','pdf_report']);assert set(out['collector_counts'].values())=={0};assert all(row(out,x)['status']=='UNAVAILABLE'for x in ['packet_capture','tcp_traceroute','pdf_report']);return out
def external_guard():
 out=cli(['tcp_connect'],'192.0.2.1',443,expect=1);assert out.get('errors');return out
def tcp(host,family,success):
 with socket.socket(family,socket.SOCK_STREAM)as owned:
  owned.bind((host,0));port=owned.getsockname()[1]
  if success:owned.listen(1)
  out=cli(['tcp_connect'],host,port);measurement=out['measurements']['tcp_connect'];assert measurement['outcome']==('CONNECTED'if success else'REFUSED'),measurement['outcome'];assert out['collector_counts']=={'host_network_snapshot':0,'tcp_connect':1,'icmp_ping':0};assert measurement['application_bytes_sent']==0
  if success:
   owned.settimeout(2)
   with owned.accept()[0]as peer:
    peer.settimeout(2);assert peer.recv(1)==b'', 'unexpected application bytes or retained socket'
   assert measurement['local_address'];assert row(out,'tcp_connect')['status']=='PASS'
  else:assert measurement['error_code']==10061;assert row(out,'tcp_connect')['status']=='FAIL'
  assert all(x['status']=='SKIPPED_BY_USER'for x in out['feature_results']if x['feature_id']!='tcp_connect');return out
def icmp(host):
 out=cli(['icmp_ping'],host);m=out['measurements']['icmp_ping'];assert m['outcome']=='REPLY',m['outcome'];assert m['ip_status']==0;assert isinstance(m['rtt_ms'],int);assert out['collector_counts']=={'host_network_snapshot':0,'tcp_connect':0,'icmp_ping':1};assert row(out,'icmp_ping')['status']=='PASS';return out
def shared_host():
 out=cli(['nic_inventory','route_table']);assert out['collector_counts']=={'host_network_snapshot':1,'tcp_connect':0,'icmp_ping':0};nic=out['measurements']['nic_inventory'];routes=out['measurements']['route_table'];assert nic==routes;assert isinstance(nic['adapters'],list)and nic['adapters'];assert isinstance(nic['routes'],list)and nic['routes'];assert isinstance(nic['selected_route'],dict);assert not nic['errors'], 'host snapshot component errors';assert row(out,'nic_inventory')['status']=='PASS';assert row(out,'route_table')['status']=='PASS';return out
case('empty_selection_no_collectors',empty);case('unsupported_no_capture_or_trace',unsupported);case('nonloopback_rejected_before_calls',external_guard)
for family,host,suffix in [(socket.AF_INET,'127.0.0.1','v4'),(socket.AF_INET6,'::1','v6')]:
 case('tcp_success_'+suffix+'_no_application_bytes_eof',lambda h=host,f=family:tcp(h,f,True))
 case('tcp_refused_'+suffix+'_raw_10061',lambda h=host,f=family:tcp(h,f,False))
 case('icmp_real_reply_'+suffix,lambda h=host:icmp(h))
case('shared_host_snapshot_once_native_route',shared_host)
report={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'executable':str(args.exe),'executed':len(rows),'passed':sum(x['passed']for x in rows),'failed':sum(not x['passed']for x in rows),'cases':rows,'scope':'owned IPv4/IPv6 loopback + read-only local adapter/route APIs only; no operations settings','full_g2_accepted':False}
# Preserve every execution separately, including failures and raw local identifiers; artifacts ignored by Git.
stamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder=R/'artifacts'/('g2a-live-'+stamp);folder.mkdir(exist_ok=False);(folder/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');(folder/'raw-local-only.json').write_text(json.dumps(raw,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(report,ensure_ascii=False,indent=2));print('evidence_folder',folder);raise SystemExit(bool(report['failed']))
