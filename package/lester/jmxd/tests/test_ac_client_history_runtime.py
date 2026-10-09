#!/usr/bin/env python3
"""Real SQLite restart, transaction, attribution and missing-measurement tests."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = Path(os.environ.get('AC_SURVEY_TEST_PREFIX', '/opt/homebrew/opt/json-c'))
MAC = 'AA:BB:CC:DD:EE:01'


def main():
    with tempfile.TemporaryDirectory(prefix='ac-client-history-') as tmp:
        tmp = Path(tmp)
        binary, database = tmp / 'fixture', tmp / 'history.db'
        cmd = [os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-I' + str(PREFIX / 'include'), str(ROOT / 'tests/ac_client_history_fixture.c'),
               str(ROOT / 'src/ac/ac_client_history.c'), '-L' + str(PREFIX / 'lib'),
               '-Wl,-rpath,' + str(PREFIX / 'lib'), '-ljson-c', '-lsqlite3', '-lm', '-o', str(binary)]
        subprocess.run(cmd, check=True)
        now = int(time.time())

        def call(**value):
            r = subprocess.run([str(binary), str(database)], input=json.dumps(value),
                               text=True, capture_output=True, check=True)
            return json.loads(r.stdout)

        def put(t, packets=100, retries=10, ap='ap-one', epoch='boot-one', connected=None,
                signal=-62, stale=False, rollback=False, survey_time=None, source='iw_station_dump'):
            station = dict(mac=MAC, interface='wlan0', source=source, observed_at=t,
                           connected_time_seconds=connected if connected is not None else t - now + 1000,
                           tx_packets=packets, tx_retries=retries, tx_bytes=packets * 64,
                           rx_bytes=100, signal_dbm=signal, stale=stale)
            snap = dict(stale=False, stations=[station],
                        ssids=[dict(interface='wlan0', radio_id='phy0')],
                        radios=[dict(id='phy0', survey=dict(observed_at=survey_time or t,
                            air_stats=dict(source='apstats_radio', available=True, obss_util_pct=23)))])
            return call(operation='ingest', ap_id=ap, epoch=epoch, observed=t, received=t,
                        snapshot=snap, rollback=rollback)

        def query(start=now-60, end=now+60, limit=256, after_id=0, mac=MAC, current=None):
            return call(operation='query', mac=mac, start=start*1000, end=end*1000,
                        limit=limit, after_id=after_id, now=(current or max(now, end))*1000)

        assert put(now)['rc'] == 0
        assert put(now)['rc'] == 0
        assert put(now+10, 180, 30)['rc'] == 0
        assert put(now+15, 200, 40, rollback=True)['rc'] == 0
        result = query()
        rows = result['client_health']['history']
        assert len(rows) == 2, 'duplicate and rolled-back telemetry must not append'
        assert rows[0]['tx_retry_pct'] is None and rows[1]['tx_retry_pct'] == 20
        assert rows[0]['activity_pct'] is None
        assert rows[1]['activity_pct'] == 100
        assert result['client_health']['activity']['valid_intervals'] == 1
        assert result['device_health']['history'][1]['interference_pct'] == 23
        assert result['attachment_history']['history'][1]['ap_id'] == 'ap-one'
        assert not result['person']['available'] and not result['site_dns']['available']
        page1 = query(limit=1)
        page2 = query(limit=1, after_id=page1['client_health']['next_after_id'])
        assert page1['client_health']['has_more'] and not page2['client_health']['has_more']
        assert page2['client_health']['history'][0]['tx_retry_pct'] == 20, 'previous page sample must remain delta baseline'
        assert page1['client_health']['activity'] == page2['client_health']['activity'], 'activity summary describes the whole window'
        assert not query(mac='aa:bb:cc:dd:ee:02')['client_health']['available']
        assert len(query(mac=MAC.lower())['client_health']['history']) == 2
        put(now+20, 240, 40, ap='ap-two')
        put(now+30, 250, 45, ap='ap-two', epoch='boot-two')
        put(now+40, 1, 1, ap='ap-two', epoch='boot-two')
        put(now+50, 10, 2, ap='ap-two', epoch='boot-two', connected=1)
        put(now+500, 20, 3, ap='ap-two', epoch='boot-two')
        put(now+510, 30, 4, ap='ap-two', epoch='boot-two', stale=True)
        rows = query(end=now+520)['client_health']['history']
        assert [r['retry_reason'] for r in rows[2:]] == [
            'attachment_or_session_changed', 'attachment_or_session_changed',
            'counter_reset', 'association_changed', 'sample_gap', 'incomplete_sample']
        assert rows[-1]['signal_dbm'] is None and not rows[-1]['complete']
        put(now+520, 40, None, source='hostapd_control', signal=None, survey_time=now)
        r = query(end=now+530)
        assert r['client_health']['history'][-1]['signal_dbm'] is None
        assert r['device_health']['history'][-1]['interference_pct'] is None
        assert r['attachment_history']['history'][0]['ap_id'] == 'ap-one'
        assert r['attachment_history']['history'][2]['ap_id'] == 'ap-two'
        assert query(limit=257)['client_health']['reason'] == 'invalid_history_query'
        put(now+8*86400)
        assert query(current=now+8*86400)['client_health']['reason'] == 'outside_retention'
        with sqlite3.connect(database) as db:
            assert db.execute('SELECT COUNT(*) FROM ac_client_health_samples').fetchone()[0] == 1
        print('ok: restart persistence; duplicate/rollback; missing/null; retry delta; roam/epoch/reset/gap; historical AP/radio; pagination; retention')


if __name__ == '__main__':
    main()
