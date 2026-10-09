#!/usr/bin/env python3
"""Production container worker with controlled LXC state/failure executables."""
import json, os, sqlite3, subprocess, tempfile, time, sys, signal
from pathlib import Path
from test_container_service_runtime import compile_fixture

def main():
 if sys.platform != "linux":
  print("SKIP: production worker identity/cancellation requires Linux /proc");return
 with tempfile.TemporaryDirectory(prefix='lxc-jobs-') as directory:
  t=Path(directory).resolve();root=t/'containers';root.mkdir();b=t/'bin';b.mkdir();db=t/'jobs.db'
  exe=compile_fixture(t,db);record=t/'calls';state=t/'state';state.write_text('STOPPED')
  (root/'sample').mkdir();(root/'sample/config').write_text('lxc.net.0.type = empty\n')
  script='''#!/usr/bin/env python3
import os,sys,json,time
from pathlib import Path
cmd=Path(sys.argv[0]).name;root=Path(os.environ['LXC_TEST_ROOT']);state=root/'state'
with (root/'calls').open('a') as f:f.write(json.dumps([cmd,*sys.argv[1:]])+'\\n')
if cmd=='lxc-config':print(root/('elsewhere' if (root/'changed-default').exists() else 'containers'))
elif cmd=='lxc-info':print(state.read_text())
else:
 if (root/'slow').exists():time.sleep(20)
 if (root/'fail').exists():sys.exit(1)
 if (root/'lie').exists():sys.exit(0)
 if cmd=='lxc-start':state.write_text('RUNNING')
 elif cmd=='lxc-stop':state.write_text('STOPPED')
 elif cmd=='lxc-destroy':
  (root/'containers/sample/config').unlink();(root/'containers/sample').rmdir()
'''
  for name in ['lxc-config','lxc-info','lxc-start','lxc-stop','lxc-destroy']:
   (b/name).write_text(script);(b/name).chmod(0o755)
  env=dict(os.environ,PATH=str(b)+':'+os.environ['PATH'],LXC_TEST_ROOT=str(t))
  def call(*args):
   p=subprocess.run([str(exe),*args],env=env,text=True,capture_output=True);assert p.stdout,(args,p.stderr)
   return json.loads(p.stdout)
  def submit(action,**kw):return call('lxc-action','sample',action,json.dumps({'confirm':True,**kw}))
  def wait(job):
   for _ in range(100):
    d=call('lxc-get',job)['data']
    if d.get('state') not in ('running','queued'):return d
    time.sleep(.08)
   raise AssertionError(('timeout',d))
  assert call('lxc-action','sample','start','{}')['error']=='confirmation_required'
  assert submit('start',arbitrary='bad')['error']=='invalid_action_fields'
  assert submit('start',identity='stale')['error']=='container_identity_changed'
  start=submit('start');assert start['engine']=='lxc' and '/lxc/jobs/' in start['status_endpoint'],start
  started=wait(start['job_id']);assert started['state']=='success',started
  assert submit('destroy')['error']=='container_must_be_stopped'
  assert submit('stop',force=True)['error']=='force_confirmation_required'
  restart=wait(submit('restart')['job_id']);assert restart['state']=='success',restart
  calls=[json.loads(x) for x in record.read_text().splitlines()]
  assert any(x[0]=='lxc-stop' and '--nokill' in x for x in calls)
  assert wait(submit('stop')['job_id'])['state']=='success'
  (t/'lie').touch();lie=wait(submit('start')['job_id']);assert lie['state']=='failed' and lie['error']=='lxc_state_not_confirmed',lie;(t/'lie').unlink()
  (t/'slow').touch();slow=submit('start');time.sleep(.2)
  assert submit('start')['error']=='container_operation_busy'
  assert call('docker-get',slow['job_id'])['data']['error']=='container_job_not_found'
  assert call('docker-list')['data']['items']==[]
  assert call('cancel',slow['job_id'])['error']=='container_job_not_found'
  cancelled=call('lxc-cancel',slow['job_id']);assert cancelled['state']=='cancelled',cancelled
  (t/'slow').unlink()
  (t/'elsewhere').mkdir();(t/'changed-default').touch()
  cancelled_job=wait(slow['job_id']);assert cancelled_job['state']=='cancelled'
  assert cancelled_job['result']['remaining_object'] is True and cancelled_job['result']['state']=='STOPPED',cancelled_job
  (t/'changed-default').unlink()
  (t/'slow').touch();interrupted=submit('start')
  for _ in range(100):
   with sqlite3.connect(db) as connection:row=connection.execute('SELECT worker_pid FROM container_job WHERE id=?',(interrupted['job_id'],)).fetchone()
   if row and row[0]>1:break
   time.sleep(.02)
  assert row and row[0]>1
  os.killpg(row[0],signal.SIGKILL)
  (t/'slow').unlink();time.sleep(.1)
  lost=wait(interrupted['job_id']);assert lost['state']=='failed' and lost['error']=='worker_interrupted',lost
  assert lost['result']['remaining_object'] is True and lost['result']['state']=='STOPPED',lost
  assert wait(submit('destroy')['job_id'])['state']=='success'
  assert all(x['engine']=='lxc' for x in call('lxc-list')['data']['items'])
  print('PASS: confirmation/identity/fields, start-stop-restart, graceful no-kill, false-success rejection, serialization, cancel/interruption with remaining object, engine isolation, precise destroy')
if __name__=='__main__':main()
