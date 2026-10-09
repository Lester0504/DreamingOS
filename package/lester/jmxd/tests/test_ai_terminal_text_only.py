#!/usr/bin/env python3
"""Real runtime, loopback model and Unix inference peers. No production services.
Run with AI_TERMINAL_FIXTURE pointing at ai_terminal_text_only_fixture.c's binary.
The fixture redirects all stores to its /tmp directory; tests never call a device.
"""
import json, os, socket, socketserver, struct, subprocess, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

calls=[]
scenario={}
function={'id':'call1','type':'function','function':{'name':'fixture_probe','arguments':'{}'}}
class Provider(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        q=json.loads(self.rfile.read(int(self.headers['Content-Length'])));calls.append(q)
        if '/fail/' in self.path:
            self.send_response(503);self.end_headers();self.wfile.write(b'{"error":{"message":"fixture unavailable"}}');return
        shape=scenario['shape'];provider=scenario['provider'];tool=scenario['tool']
        # A normal workbench may run the low-risk tool and then receive the reply.
        if scenario.get('normal') and len(calls)>1:tool=False
        if provider=='gemini':
            obj={'candidates':[{'content':{'role':'model','parts':[{'functionCall':{'name':'fixture_probe','args':{}}}] if tool else [{'text':'fixture reply'}]},'finishReason':'STOP'}]}
            events=[obj]
        elif provider=='anthropic':
            block={'type':'tool_use','id':'call1','name':'fixture_probe','input':{}} if tool else {'type':'text','text':'fixture reply'}
            obj={'content':[block],'stop_reason':'tool_use' if tool else 'end_turn'}
            events=[{'type':'content_block_start','index':0,'content_block':block},{'type':'content_block_delta','index':0,'delta':{'type':'input_json_delta','partial_json':'{}'}}] if tool else [{'type':'content_block_delta','delta':{'type':'text_delta','text':'fixture reply'}}]
        elif shape=='responses':
            block={'type':'function_call','call_id':'call1','name':'fixture_probe','arguments':'{}'}
            obj={'output':[block],'status':'completed'} if tool else {'output_text':'fixture reply','status':'completed'}
            events=[{'type':'response.output_item.done','output_index':0,'item':block}] if tool else [{'type':'response.output_text.delta','delta':'fixture reply'}]
            events.append({'type':'response.completed','response':{'status':'completed'}})
        else:
            msg={'role':'assistant','content':None,'tool_calls':[function]} if tool else {'role':'assistant','content':'fixture reply'}
            obj={'choices':[{'message':msg,'finish_reason':'tool_calls' if tool else 'stop'}]}
            delta={'tool_calls':[dict(function,index=0)]} if tool else {'content':'fixture reply'}
            events=[{'choices':[{'delta':delta,'finish_reason':'tool_calls' if tool else 'stop'}]}]
        stream=q.get('stream') or ':streamGenerateContent' in self.path
        data=(''.join('data: '+json.dumps(e)+'\n\n' for e in events)+'data: [DONE]\n\n').encode() if stream else json.dumps(obj).encode()
        self.send_response(200);self.send_header('Content-Type','text/event-stream' if stream else 'application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

def exact(s,n):
    b=b''
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:raise EOFError()
        b+=c
    return b

def send(s,j):
    b=json.dumps(j).encode();s.sendall(struct.pack('!I',len(b))+b)
class Local(socketserver.BaseRequestHandler):
    def handle(self):
        q=json.loads(exact(self.request,struct.unpack('!I',exact(self.request,4))[0]));calls.append(q)
        if q['op']=='status':send(self.request,{'ok':True,'data':{'ready':True,'model':{'loaded_id':'fixture'}}})
        elif q['op']=='cancel':send(self.request,{'ok':True})
        else:
            send(self.request,{'event':'started'})
            send(self.request,{'event':'tool_call','tool_calls':[function]} if scenario['tool'] else {'event':'delta','delta':'fixture reply'})
            if not scenario['tool']:send(self.request,{'event':'completed'})


def main():
    binary=os.environ['AI_TERMINAL_FIXTURE'];home=Path(binary).parent;unix=home/'local.sock'
    unix.unlink(missing_ok=True)
    server=ThreadingHTTPServer(('127.0.0.1',0),Provider);local=socketserver.ThreadingUnixStreamServer(str(unix),Local)
    for s in [server,local]:threading.Thread(target=s.serve_forever,daemon=True).start()
    env=dict(os.environ,AI_TEST_LOCAL_SOCKET=str(unix),AI_TEST_BASE=f'http://127.0.0.1:{server.server_port}',LD_LIBRARY_PATH='/usr/lib/x86_64-linux-gnu')
    count=0
    def run(mode,body,provider='openai-compatible',shape='chat_completions',tool=False,normal=False,failover=False):
        nonlocal count
        calls.clear();scenario.update(provider=provider,shape=shape,tool=tool,normal=normal)
        e=dict(env,AI_TEST_PROVIDER=provider,AI_TEST_SHAPE=shape)
        if failover:e['AI_TEST_FAILOVER']='1'
        result=subprocess.run([binary,mode,json.dumps(body)],env=e,capture_output=True,text=True,timeout=15)
        assert result.returncode==0,(result.stdout,result.stderr)
        output=result.stdout;stats=json.loads(output.split('FIXTURE_STATS ')[-1])
        if normal:
            assert stats['tool_calls']==1,(output,calls)
            assert any(q.get('tools') for q in calls),calls
            assert 'fixture reply' in output,output
        else:
            assert stats=={'tool_calls':0,'tool_registry':0,'authorizations':0},(stats,output)
            assert all(not q.get('tools') for q in calls),calls
            if tool or mode.startswith('resume') or mode=='execute-guard':assert 'tools_disabled' in output,output
            elif body.get('terminal_context',{}).get('mode')!='text_only':assert 'terminal_context_invalid' in output,output
            else:assert 'fixture reply' in output,output
        assert 'pending_authorization' not in output or 'pending_authorizations' in output,output
        count+=1;print('PASS',mode,provider,shape,'tool' if tool else 'text','normal' if normal else 'terminal','failover' if failover else '')
    body={'message':'fixture question','conversation_id':'fixture','terminal_context':{'mode':'text_only'},'tool_policy':'disabled'}
    try:
        for provider,shape in [('openai-compatible','chat_completions'),('openai','responses'),('anthropic','chat_completions'),('gemini','chat_completions')]:
            for mode in ['chat','stream']:
                for tool in [False,True]:run(mode,body,provider,shape,tool)
        for mode in ['chat','stream']:
            for tool in [False,True]:run(mode,dict(body,execution_backend='local'),tool=tool)
        for mode in ['resume','resume-stream','execute-guard']:run(mode,body)
        for mode in ['chat','stream']:
            run(mode,{'message':'fixture question','conversation_id':'fixture'},tool=True,normal=True)
            run(mode,dict(body,terminal_context={'mode':'execute'}))
        run('chat',body,tool=True,failover=True)
        run('chat',body,tool=False,failover=True)
        print(f'{count} runtime cases passed; all terminal cases had zero registry/tool/authorization calls')
    finally:
        server.shutdown();local.shutdown();server.server_close();local.server_close();unix.unlink(missing_ok=True)
if __name__=='__main__':main()
