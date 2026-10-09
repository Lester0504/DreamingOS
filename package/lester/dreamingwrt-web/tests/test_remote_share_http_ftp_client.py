"""Run inside the isolated QEMU fixture after copying ready-for-ftp.json to request.json."""
from pathlib import Path
import ftplib
import io
import json

base = Path('/tmp/remote-share-ftp-front')
assert (base / '.fixture').read_text().strip() == 'isolated-remote-share-ftp-front-qemu'
request = json.loads((base / 'request.json').read_text())
assert request['path'] == str(base / 'data')
payload = bytes(range(256)) * 257 + b'Browser to real FTP\x00\xff' + request['runId'].encode()
with ftplib.FTP() as ftp:
    ftp.connect('127.0.0.1', 2121, timeout=25)
    ftp.login('dwshare_browserftp', 'Browser-ftp-fixture-1005')
    ftp.cwd('browser-files')
    ftp.storbinary('STOR browser-roundtrip.bin', io.BytesIO(payload))
    data = io.BytesIO()
    ftp.retrbinary('RETR browser-roundtrip.bin', data.write)
    assert data.getvalue() == payload
assert (base / 'data/browser-roundtrip.bin').read_bytes() == payload
result = {**request, 'result': 'PASS', 'bytes': len(payload),
          'directory': 'browser-files', 'login': 'dwshare_browserftp'}
pending = base / 'evidence/ftp-transfer.json.tmp'
pending.write_text(json.dumps(result))
pending.replace(base / 'evidence/ftp-transfer.json')
print(json.dumps(result), flush=True)
