"""Apply rustc's exact casing suggestions by local aliases, then rustfmt; no lint suppression."""
import pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];p=R/'crates/npi-probes/src/host.rs';s=p.read_text(encoding='utf-8')
pairs=[('IfOperStatusUp','IF_OPER_STATUS_UP'),('IfOperStatusDown','IF_OPER_STATUS_DOWN'),('IfOperStatusTesting','IF_OPER_STATUS_TESTING'),('IfOperStatusUnknown','IF_OPER_STATUS_UNKNOWN'),('IfOperStatusDormant','IF_OPER_STATUS_DORMANT'),('IfOperStatusNotPresent','IF_OPER_STATUS_NOT_PRESENT'),('IfOperStatusLowerLayerDown','IF_OPER_STATUS_LOWER_LAYER_DOWN')]
if any(re.search(r'(?m)^\s*'+old+r'\s*=>',s)for old,new in pairs):
 replacement='Ndis::{\n            IF_OPER_STATUS,\n'+''.join('            '+old+' as '+new+',\n'for old,new in pairs)+'        }'
 s,count=re.subn(r'Ndis::\{.*?\}',lambda _:replacement,s,count=1,flags=re.S);assert count==1
 for old,new in pairs:s=re.sub(r'(?m)^(\s*)'+old+r'(\s*=>)',lambda m:m[1]+new+m[2],s)
 p.write_text(s,encoding='utf-8',newline='\n')
subprocess.run(['cargo','fmt'],cwd=R,check=True)
print('Native IF_OPER_STATUS constants locally aliased; rustfmt applied, behavior unchanged; independent revalidation required')
