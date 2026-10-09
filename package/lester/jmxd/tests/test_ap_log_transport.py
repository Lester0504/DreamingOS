"""Real APD log send/ACK routine over TLS: only bound durable ACKs dequeue."""
from pathlib import Path
import json
import socket
import ssl
import struct
import subprocess
import threading
import pytest
from apd_test_deps import package_flags
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture(scope='module')
def transport(tmp_path_factory):
    out=tmp_path_factory.mktemp('ap-log-tls')
    command=['cc','-std=gnu11','-D_GNU_SOURCE','-O1','-ffunction-sections','-fdata-sections',
             '-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter',
             str(ROOT/'tests/ap_log_transport_fixture.c'),str(ROOT/'src/ap_control_wire.c'),
             '-Wl,--gc-sections',*package_flags('json-c','openssl'),'-lpthread','-o',str(out/'fixture')]
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==0,result.stderr[-8000:]
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(out/'key.pem'),
                    '-out',str(out/'cert.pem'),'-days','1','-subj','/CN=ap-log-fixture'],check=True,capture_output=True)
    return out

def read_n(sock,n):
    data=b''
    while len(data)<n:
        block=sock.recv(n-len(data))
        if not block: raise EOFError
        data+=block
    return data

@pytest.mark.parametrize('case',['success','negative','wrong_sequence','wrong_ap','wrong_epoch','disconnect'])
def test_bound_ack(transport,case):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(transport/'cert.pem',transport/'key.pem')
    errors=[]
    def server():
        try:
            conn,_=listener.accept()
            with ctx.wrap_socket(conn,server_side=True) as sock:
                size=struct.unpack('!I',read_n(sock,4))[0]
                message=json.loads(read_n(sock,size))
                assert message['kind']=='log_batch' and len(message['events'])==1
                if case=='disconnect':return
                reply={k:message[k] for k in ['protocol','ap_id','session_epoch','sequence']}
                reply.update(kind='log_batch_ack',persisted=case!='negative',error='' if case!='negative' else 'storage_unavailable')
                if case=='wrong_sequence':reply['sequence']+=1
                if case=='wrong_ap':reply['ap_id']='22222222-2222-4222-8222-222222222222'
                if case=='wrong_epoch':reply['session_epoch']='b'*64
                data=json.dumps(reply).encode();sock.sendall(struct.pack('!I',len(data))+data)
        except Exception as exc:errors.append(exc)
    worker=threading.Thread(target=server);worker.start()
    result=subprocess.run([str(transport/'fixture'),str(listener.getsockname()[1]),str(transport/'cert.pem')],capture_output=True,text=True,timeout=12)
    worker.join(10);listener.close()
    assert not errors,errors
    assert result.returncode==0,result.stderr
    assert f'acked={1 if case=="success" else 0}' in result.stdout
    assert f'rc={0 if case in ("success","negative") else -1}' in result.stdout
