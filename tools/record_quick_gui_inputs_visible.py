"""승인 만료된 입력 조작은 재시도하지 않고 자기 테스트 창만 읽고 닫는다."""
import ctypes as c, datetime,json,pathlib,shutil
from ctypes import wintypes as w
R=pathlib.Path(__file__).resolve().parents[1]
p=json.loads((R/'artifacts/qg3b-gui-inputs-visible-process.json').read_text(encoding='utf-8'))
assert p['pid']==38296 and p['status']=='OWNED_VISIBLE_GUI_RUNNING_NOT_ACCEPTED'
u=c.WinDLL('user32',use_last_error=True)
u.GetWindowThreadProcessId.argtypes=[w.HWND,c.POINTER(w.DWORD)];u.GetWindowThreadProcessId.restype=w.DWORD
u.GetDlgItem.argtypes=[w.HWND,c.c_int];u.GetDlgItem.restype=w.HWND
u.SendMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM];u.SendMessageW.restype=c.c_ssize_t
u.GetWindowTextLengthW.argtypes=[w.HWND];u.GetWindowTextLengthW.restype=c.c_int
u.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,c.c_int];u.GetWindowTextW.restype=c.c_int
u.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM];u.PostMessageW.restype=w.BOOL
hwnd=9372678;pid=w.DWORD();assert u.GetWindowThreadProcessId(hwnd,c.byref(pid)) and pid.value==p['pid']
field=u.GetDlgItem(hwnd,103);size=u.GetWindowTextLengthW(field);assert 0<=size<=32769
text=c.create_unicode_buffer(size+1);assert u.GetWindowTextW(field,text,size+1)==size
checks={str(i):u.SendMessageW(u.GetDlgItem(hwnd,i),0xf0,0,0) for i in range(109,114)}
folder=R/'.harness/evidence/qg3b-visible';images={}
for name,source in [('initial.png','computer_use_fe76ca31509042b88cc47dff16c3fba5.png'),('background-type.png','computer_use_1c4ae5cb0f484cb4a95053f26537b0fd.png')]:
 src=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/images')/source;assert src.is_file()
 shutil.copyfile(src,folder/name);images[name]=str(folder/name)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'VISIBLE_RENDER_OBSERVED_INPUT_ACTION_CONSENT_TIMED_OUT_NOT_ACCEPTED',
 'pid':p['pid'],'window_handle':hwnd,'binary_sha256':p['binary_sha256'],'screenshots':images,
 'render_observations':['Korean input/plan-only notice visible','target/options/actions/plan areas visible','start/stop/save visibly disabled','initial layout readable at this captured size only'],
 'background_typing':{'requested':'127.0.0.1:080\r\n[::1]:443','observed':text.value,'matched':text.value=='127.0.0.1:080\r\n[::1]:443',
 'delivery':'PostMessage synthetic event route','not_clipboard_test':True},
 'observed_check_states_by_control_id':checks,
 'checkbox_initialization_limit':'visible capture Trace checked differs from ignored hidden default witness; cause not established; do not certify untouched visible defaults',
 'blocked_action':{'tool':'computer_use','action':'set_value','element':0,'result':'Action timed out without user response; user has NOT consented',
 'retry_or_alternative_attempted':False},
 'unverified':['exact multiline user input/Enter behavior','visible add/replace/delete/plan operation sequence','Tab traversal','resize/scroll usability','DPI conditions','OS variants'],
 'owned_window_close_requested':bool(u.PostMessageW(hwnd,0x0010,0,0)),
 'native_hidden_tests_passed':4,'visible_functional_acceptance':False,'root_integrated':False,'accepted':False}
assert record['owned_window_close_requested']
out=R/'artifacts/qg3b-gui-inputs-visible-observation.json';assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'input_matches':record['background_typing']['matched'],'close_requested':True,'accepted':False},ensure_ascii=False))
