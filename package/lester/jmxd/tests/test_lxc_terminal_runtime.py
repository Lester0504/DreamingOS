#!/usr/bin/env python3
"""Real LXC in an explicitly prepared isolated namespace; uses only test container.
TM_BINARY selects a native runtime built with TM_LEASE_SECONDS=4.
LXC_TEST_ROOT and LXC_TEST_NAME must identify the approved disposable container.
"""
import base64,json,os,socket,subprocess,time,unittest
from pathlib import Path
from test_terminal_manager_runtime import Runtime,WS

class LXC(Runtime):
 @classmethod
 def setUpClass(cls):
  cls.root=os.environ['LXC_TEST_ROOT'];cls.name=os.environ['LXC_TEST_NAME']
  cls.cli=['-P',cls.root,'-n',cls.name]
  subprocess.run(['lxc-start',*cls.cli,'-d'],check=True)
  super().setUpClass()
 @classmethod
 def tearDownClass(cls):
  super().tearDownClass()
  subprocess.run(['lxc-stop',*cls.cli,'-k'],check=True)
 def identity(self):
  stat=(Path(self.root)/self.name).stat();return f'{stat.st_dev}:{stat.st_ino}'
 def start_lxc(self,**params):
  response=self.rpc('lxc/sessions','POST',dict(container_id=self.name,identity=self.identity(),shell='/bin/sh',workspace_id='lxc-test',**params))
  self.assertEqual(response['status'],202,response);session=response['data']
  a,b=socket.socketpair()
  response=self.rpc(f"lxc/sessions/{session['id']}/ws",body={'websocket_key':base64.b64encode(os.urandom(16)).decode()},passed=a);a.close()
  self.assertTrue(response['data']['fd_owned'],response);ws=WS(b)
  self.addCleanup(ws.peer.close);self.addCleanup(lambda:self.rpc(f"lxc/sessions/{session['id']}/disconnect",'POST'))
  return session,ws
 def stopped(self,pid):
  for _ in range(60):
   if not Path(f'/proc/{pid}').exists():return
   time.sleep(.05)
  self.fail(f'attach shell still present: {pid}')
 def test_lxc_01_tty_scope_close(self):
  self.assertTrue(self.rpc('lxc/capabilities')['data']['connect'])
  session,ws=self.start_lxc();ready=ws.until_state('ready');pid=ready['host']['attached_pid']
  ws.send({'type':'resize','cols':91,'rows':27})
  ws.send({'type':'input','data':"hostname; stty size; printf '\\344\\270\\255\\346\\226\\207-LXC-TTY-OK\\n'\n"})
  output=b''
  for _ in range(40):
   op,data=ws.event()
   if op==2:
    output+=data
    if b'27 91' in output and '中文-LXC-TTY-OK'.encode() in output:break
   elif op==1 and data.get('state')=='disconnected':break
  self.assertIn(self.name.encode(),output);self.assertIn('中文-LXC-TTY-OK'.encode(),output);self.assertIn(b'27 91',output)
  path=f"lxc/sessions/{session['id']}"
  self.assertEqual(self.rpc(path,owner='other')['status'],404)
  self.assertEqual(self.rpc(path,manage=False)['status'],403)
  for prefix in ['sessions/','docker/sessions/']:
   self.assertEqual(self.rpc(prefix+session['id'])['status'],404)
  for prefix in ['sessions','docker/sessions']:
   self.assertNotIn(session['id'],[v['id'] for v in self.rpc(prefix)['data']['items']])
  for suffix in ['/system-info','/processes','/files']:
   self.assertEqual(self.rpc(path+suffix)['status'],422)
  self.rpc(path+'/lease','POST');ws.peer.close();self.stopped(pid)
  self.assertEqual(subprocess.check_output(['lxc-info',*self.cli,'-sH'],text=True).strip(),'RUNNING')
 def test_lxc_02_lease(self):
  session,ws=self.start_lxc();ready=ws.until_state('ready')
  ended=ws.until_state('disconnected');self.assertEqual(ended['reason'],'authorization_lease_expired');self.stopped(ready['host']['attached_pid'])
 def test_lxc_03_disconnect(self):
  session,ws=self.start_lxc();ready=ws.until_state('ready')
  self.rpc(f"lxc/sessions/{session['id']}/disconnect",'POST');ws.until_state('closed');self.stopped(ready['host']['attached_pid'])
 def test_lxc_04_invalid_and_stale(self):
  body=dict(container_id=self.name,identity=self.identity(),workspace_id='test')
  for extra in [dict(host={'type':'local'}),dict(shell='/bin/sh -c id'),dict(command='id'),dict(container_id='../etc')]:
   self.assertEqual(self.rpc('lxc/sessions','POST',{**body,**extra})['status'],422)
  self.assertEqual(self.rpc('lxc/sessions','POST',body,manage=False)['status'],403)
  self.assertEqual(self.rpc('sessions','POST',{'host':{'type':'lxc','name':'bad'},'workspace_id':'test'})['status'],422)
  response=self.rpc('lxc/sessions','POST',{**body,'identity':'0:0'});session=response['data'];a,b=socket.socketpair()
  self.rpc(f"lxc/sessions/{session['id']}/ws",body={'websocket_key':base64.b64encode(os.urandom(16)).decode()},passed=a);a.close()
  ws=WS(b);self.assertEqual(ws.until_state('failed')['reason'],'container_identity_changed');b.close()
 def test_lxc_05_missing_shell_and_stop(self):
  response=self.rpc('lxc/sessions','POST',{'container_id':self.name,'identity':self.identity(),'workspace_id':'test','shell':'/bin/bash'})
  session=response['data'];a,b=socket.socketpair();self.rpc(f"lxc/sessions/{session['id']}/ws",body={'websocket_key':base64.b64encode(os.urandom(16)).decode()},passed=a);a.close()
  ws=WS(b);self.assertEqual(ws.until_state('failed')['reason'],'lxc_shell_unavailable');b.close()
  session,ws=self.start_lxc();ready=ws.until_state('ready')
  subprocess.run(['lxc-stop',*self.cli,'-k'],check=True)
  try:
   ws.until_state('disconnected');self.stopped(ready['host']['attached_pid'])
   session,ws=self.start_lxc();self.assertEqual(ws.until_state('failed')['reason'],'lxc_container_not_running')
  finally:subprocess.run(['lxc-start',*self.cli,'-d'],check=True)

if __name__=='__main__':
 suite=unittest.TestSuite(LXC(n) for n in unittest.defaultTestLoader.getTestCaseNames(LXC) if n.startswith('test_lxc_'))
 raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
