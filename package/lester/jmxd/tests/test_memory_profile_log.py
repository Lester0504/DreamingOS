"""Run the production compact retention SQL against old and newly ingested history."""
from pathlib import Path
import re, sqlite3, json

source=(Path(__file__).resolve().parents[1]/'src/logd/logd_db.c').read_text()
def sql(prefix):
    matches=re.findall(r'logd_exec\(("(?:[^"\\]|\\.)*")\)',source)
    return next(json.loads(s) for s in matches if json.loads(s).startswith(prefix))
def test_new_history_only():
    db=sqlite3.connect(':memory:');mode=[0]
    db.create_function('dw_memory_compact',0,lambda:mode[0]);db.execute('PRAGMA foreign_keys=ON')
    db.execute('CREATE TABLE log_events(id TEXT PRIMARY KEY, ts INTEGER)')
    db.execute("INSERT INTO log_events VALUES('legacy',1)")
    for prefix in ['CREATE TABLE IF NOT EXISTS log_compact_deadlines','CREATE INDEX IF NOT EXISTS idx_log_compact_expiry','CREATE TRIGGER IF NOT EXISTS log_compact_new_detail']:db.execute(sql(prefix))
    mode[0]=1;db.execute("INSERT INTO log_events VALUES('new-compact',2)")
    assert db.execute('SELECT id FROM log_compact_deadlines').fetchall()==[('new-compact',)]
    mode[0]=0;db.execute("INSERT INTO log_events VALUES('new-standard',3)")
    db.execute("UPDATE log_compact_deadlines SET expires_at=1")
    db.execute(sql('DELETE FROM log_events WHERE id IN (SELECT id FROM log_compact_deadlines'))
    assert db.execute('SELECT id FROM log_events ORDER BY id').fetchall()==[('legacy',),('new-standard',)]
    assert not db.execute('SELECT * FROM log_compact_deadlines').fetchall()
    db.close();print('compact retention: only newly marked history expires; legacy and standard rows preserved: PASS')
if __name__=='__main__':test_new_history_only()
