#!/usr/bin/env python3
"""Actual production PKI/task/AP credential functions, SQLite and TLS 1.3."""
import os, sys, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
flags=[]
for name in ('openssl@3','json-c'):
    prefix=Path('/opt/homebrew/opt')/name
    if prefix.exists(): flags += ['-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-Wl,-rpath,'+str(prefix/'lib')]
with tempfile.TemporaryDirectory(prefix='ac-cert-lifecycle-') as raw:
    base=Path(raw);base.chmod(0o700);binary=base/'fixture'
    authorization=(root/'src/ac/ac_db.c').read_text()
    start=authorization.index('int ac_db_certificate_peer_authorize(')
    end=authorization.index('\n}\n',start)+3
    peer_source=base/'peer_authorize.c'
    peer_source.write_text('''#include <sqlite3.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
static sqlite3 *g_ac_db;
static int64_t ac_now_s(void) { return time(NULL); }
static int ac_uuid_valid(const char *value) { return value && strlen(value)==36; }
''' + authorization[start:end] + '''
int fixture_peer_authorize(sqlite3 *db, const char *certificate, const char *ap,
                           const unsigned char fingerprint[32]) {
    g_ac_db=db;
    return ac_db_certificate_peer_authorize(certificate,ap,fingerprint,1);
}
''')
    command=[os.environ.get('CC','cc'),'-std=c11','-D_DARWIN_C_SOURCE' if sys.platform=='darwin' else '-D_GNU_SOURCE','-DAC_PKI_TEST_STANDALONE','-DAPD_ENROLLMENT_TEST_STANDALONE','-Wall','-Wextra','-Werror',*flags,str(root/'tests/ac_certificate_lifecycle_fixture.c'),str(peer_source),str(root/'src/ac/ac_pki.c'),str(root/'src/ac/ac_certificate_lifecycle.c'),str(root/'src/apd/apd_enrollment.c'),str(root/'src/apd/apd_bootstrap_write.c'),str(root/'src/ap_control_wire.c'),'-lcrypto','-lssl','-ljson-c','-lsqlite3','-o',str(binary)]
    r=subprocess.run(command,capture_output=True,text=True)
    if r.returncode: print(r.stderr);raise SystemExit(r.returncode)
    r=subprocess.run([str(binary),str(base)],capture_output=True,text=True)
    print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr)
    if r.returncode == 0:
        database=(base/'tasks.db').read_bytes()
        for key in (base/'ac').rglob('*.ed25519'):
            material=key.read_bytes()
            if len(material)==32: assert material not in database, key.name
        assert b'PRIVATE KEY' not in database
        print('PASS private key bytes absent from task database and audit')
    raise SystemExit(r.returncode)
