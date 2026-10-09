#!/usr/bin/env python3
"""Real production C + SQLite tests for sampled-interval activity, not airtime."""
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = Path(os.environ.get('AC_SURVEY_TEST_PREFIX', '/opt/homebrew/opt/json-c'))
MAC = 'aa:bb:cc:dd:ee:01'


def main():
    checks = 0
    evidence = Path(os.environ['AC_CLIENT_ACTIVITY_EVIDENCE_DIR']) if os.environ.get('AC_CLIENT_ACTIVITY_EVIDENCE_DIR') else None
    if evidence:
        evidence.mkdir(parents=True, exist_ok=True)

    def check(condition, message):
        nonlocal checks
        assert condition, message
        checks += 1

    with tempfile.TemporaryDirectory(prefix='ac-client-activity-') as temporary:
        work = Path(temporary)
        binary = work / 'fixture'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(PREFIX / 'include'), str(ROOT / 'tests/ac_client_history_fixture.c'),
                        str(ROOT / 'src/ac/ac_client_history.c'), '-L' + str(PREFIX / 'lib'),
                        '-Wl,-rpath,' + str(PREFIX / 'lib'), '-ljson-c', '-lsqlite3', '-lm', '-o', str(binary)], check=True)
        base = int(time.time())
        database = None

        def case(name):
            nonlocal database
            database = work / (name + '.db')

        def call(**value):
            result = subprocess.run([str(binary), str(database)], input=json.dumps(value),
                                    text=True, capture_output=True, check=True)
            return json.loads(result.stdout)

        def put(offset, tx=0, rx=0, *, ap='ap-one', epoch='boot-one', interface='wlan0',
                radio='phy0', source='iw_station_dump', stale=False, connected=None,
                received=None, mac=MAC):
            observed = base + offset
            station = dict(mac=mac, interface=interface, source=source, observed_at=observed,
                           connected_time_seconds=offset + 1000 if connected is None else connected,
                           tx_bytes=tx, rx_bytes=rx, tx_packets=100, tx_retries=10, stale=stale)
            snapshot = dict(stations=[station], ssids=[dict(interface=interface, radio_id=radio)],
                            radios=[dict(id=radio)])
            return call(operation='ingest', ap_id=ap, epoch=epoch, observed=observed,
                        received=base + (offset if received is None else received), snapshot=snapshot)

        def query(start=0, end=600, limit=256, after=0, mac=MAC, current=None, save=None):
            result = call(operation='query', mac=mac, start=(base + start) * 1000,
                          end=(base + end) * 1000, limit=limit, after_id=after,
                          now=(base + (max(0, end) if current is None else current)) * 1000)
            if evidence and save:
                (evidence / (save + '.json')).write_text(json.dumps(result, indent=2) + '\n')
            return result['client_health']

        case('empty')
        empty = query(save='empty')
        check(empty['activity']['activity_pct'] is None and not empty['activity']['available'], 'empty window is unknown')
        check(empty['activity']['coverage_pct'] == 0 and empty['activity']['uncovered_duration_ms'] == 600000, 'empty coverage is explicit')
        put(300)
        single = query(save='single')
        check(single['history'][0]['activity_interval']['reason'] == 'no_previous_sample', 'first sample has no interval')
        check(single['activity']['valid_intervals'] == 0 and single['activity']['activity_pct'] is None, 'one sample is not idle')

        case('idle')
        for offset in [0, 300, 600]:
            put(offset)
        idle = query(save='idle')
        check(idle['activity']['activity_pct'] == 0 and idle['activity']['available'], 'valid all-idle window returns real zero')
        check(idle['activity']['valid_duration_ms'] == 600000 and idle['activity']['complete'], 'idle intervals cover the explicit window')
        check(idle['history'][1]['retry_reason'] == 'no_tx_attempts' and idle['history'][1]['activity_interval']['valid'], 'retry missing attempts do not hide valid byte counters')
        check(idle['activity']['active_intervals'] == 0 and idle['activity']['valid_intervals'] == 2, 'idle interval counts')

        case('weighted')
        for offset, tx, rx in [(0, 0, 0), (30, 0, 1), (330, 0, 1), (360, 1, 1)]:
            put(offset, tx, rx)
        weighted = query(save='partial-active')
        check(math.isclose(weighted['activity']['activity_pct'], 100 / 6), '30 + 30 active seconds / 360 valid seconds, not 2 / 3 intervals')
        check(weighted['activity']['active_intervals'] == 2 and weighted['activity']['valid_intervals'] == 3, 'weighted interval counts remain visible')
        check(weighted['activity']['coverage_pct'] == 60 and not weighted['activity']['complete'], 'unsampled tail is not idle')
        check([r['activity_pct'] for r in weighted['history']] == [None, 100, 0, 100], 'row values classify only valid intervals')
        check(weighted['history'][1]['activity_interval']['rx_bytes_delta'] == 1 and weighted['history'][3]['activity_interval']['tx_bytes_delta'] == 1, 'either direction activates the interval')
        cursor, seen = 0, []
        for _ in range(4):
            page = query(limit=1, after=cursor)
            check(page['activity'] == weighted['activity'], 'summary cannot change with cursor or page size')
            seen.extend(page['history'])
            cursor = page['next_after_id'] or cursor
        check(seen == weighted['history'], 'page boundary retains original interval classification and baseline')
        check(not query(after=10**9)['history'] and query(after=10**9)['activity'] == weighted['activity'], 'empty later page still carries full-window summary')
        clipped = query(start=15, end=360, save='boundary-clipped')
        check(clipped['history'][0]['activity_interval']['reason'] == 'interval_outside_window', 'interval straddling query start is not interpolated')
        check(clipped['activity']['valid_duration_ms'] == 330000 and clipped['activity']['active_duration_ms'] == 30000, 'only complete intervals within the requested window count')
        check(query(start=30, end=330)['activity']['activity_pct'] == 0, 'window end excludes the later active interval')
        check(query(start=30, end=30)['activity']['activity_pct'] is None, 'zero-length window has no denominator')
        with sqlite3.connect(database) as db:
            raw = db.execute('SELECT sample_json FROM ac_client_health_samples ORDER BY id').fetchall()
        query()
        with sqlite3.connect(database) as db:
            check(raw == db.execute('SELECT sample_json FROM ac_client_health_samples ORDER BY id').fetchall(), 'query leaves persisted raw history unchanged')
            check(all('activity_pct' not in json.loads(row[0]) for row in raw), 'existing schema/raw counters need no rewrite or migration')
        check(not query(mac='aa:bb:cc:dd:ee:02')['activity']['available'], 'MAC scope excludes other clients')
        check(query(mac=MAC.upper())['activity'] == weighted['activity'], 'MAC matching is case-insensitive')

        for label, mutation, expected in [
            ('missing-tx', dict(tx=None), 'byte_counters_unavailable'),
            ('missing-rx', dict(rx=None), 'byte_counters_unavailable'),
            ('invalid-byte-type', dict(rx='100'), 'byte_counters_unavailable'),
            ('stale', dict(stale=True), 'incomplete_sample'),
            ('tx-reset', dict(tx=0), 'counter_reset'),
            ('rx-reset', dict(rx=0), 'counter_reset'),
            ('roam', dict(ap='ap-two'), 'attachment_or_session_changed'),
            ('epoch', dict(epoch='boot-two'), 'attachment_or_session_changed'),
            ('interface', dict(interface='wlan1'), 'attachment_or_session_changed'),
            ('radio', dict(radio='phy1'), 'attachment_or_session_changed'),
            ('source', dict(source='hostapd_control'), 'attachment_or_session_changed'),
            ('association', dict(connected=1), 'association_changed'),
            ('association-unknown', dict(connected=-1), 'association_epoch_unknown'),
        ]:
            case(label)
            put(0, tx=10, rx=10)
            arguments = dict(tx=10, rx=10)
            arguments.update(mutation)
            put(300, **arguments)
            result = query(save=label)
            check(result['history'][1]['activity_interval']['reason'] == expected, label + ' explains invalid interval')
            check(result['history'][1]['activity_pct'] is None and result['activity']['activity_pct'] is None, label + ' must not become idle zero')

        case('recover-after-missing')
        put(0)
        put(300, rx=None)
        put(600, rx=10)
        put(900, rx=11)
        recovered = query(end=1200, save='missing-and-recovery')
        check([r['activity_pct'] for r in recovered['history']] == [None, None, None, 100], 'one missing endpoint invalidates both adjacent intervals')
        check(recovered['activity']['valid_duration_ms'] == 300000 and recovered['activity']['uncovered_duration_ms'] == 900000, 'recovery retains explicit missing coverage')

        case('recover-after-reset')
        put(0, tx=100)
        put(300, tx=1)
        put(600, tx=1)
        reset = query(save='reset-and-recovery')
        check([r['activity_pct'] for r in reset['history']] == [None, None, 0], 'reset interval is missing, subsequent stable counter can recover')
        check(reset['activity']['coverage_pct'] == 50 and reset['activity']['activity_pct'] == 0, 'known idle after reset is distinguished from reset gap')

        for label, offsets, received in [
            ('refresh-gap', [0, 600], [0, 600]),
            ('gap-over-limit', [0, 361], [0, 361]),
            ('receive-gap', [0, 300], [0, 600]),
            ('observed-backward', [300, 0], [0, 300]),
            ('receive-backward', [0, 300], [300, 0]),
        ]:
            case(label)
            for offset, receipt in zip(offsets, received):
                put(offset, rx=100, received=receipt)
            result = query(save=label)
            check(result['history'][1]['activity_interval']['reason'] == 'sample_gap', label + ' breaks continuity')
            check(result['activity']['activity_pct'] is None and result['activity']['valid_intervals'] == 0, label + ' contributes no duration')
        case('gap-limit')
        put(0)
        put(360, tx=1)
        check(query(end=360)['activity']['activity_pct'] == 100, 'existing 360 s scheduling tolerance is included')

        case('overlap')
        for offset, receipt, tx in [(0, 0, 0), (60, 60, 1), (90, 30, 2), (120, 90, 3)]:
            put(offset, tx=tx, received=receipt)
        overlap = query(end=90)
        check(overlap['history'][-1]['activity_interval']['reason'] == 'overlapping_interval', 'controller clock reversal cannot double count overlapping coverage')
        check(overlap['activity']['valid_duration_ms'] == 60000, 'coverage contains no overlapping counted intervals')

        case('hostapd-counters')
        put(0, source='hostapd_control')
        put(300, rx=1, source='hostapd_control')
        hostapd = query(end=300)
        check(hostapd['history'][1]['retry_reason'] == 'retry_counters_unavailable' and hostapd['activity']['activity_pct'] == 100, 'real hostapd byte counters work without iw retry semantics')

        case('many-pages')
        for i in range(270):
            put(i * 30, tx=i // 3)
        page1 = query(end=269 * 30)
        page2 = query(end=269 * 30, after=page1['next_after_id'])
        check(len(page1['history']) == 256 and len(page2['history']) == 14, 'actual maximum-page boundary')
        check(page1['has_more'] and not page2['has_more'], 'has_more and cursor remain correct')
        check(page1['activity'] == page2['activity'] and page1['activity']['valid_intervals'] == 269, 'whole-window denominator includes samples beyond first page')
        check(page1['activity']['active_intervals'] == 89, 'all pages contribute activity once')
        check(page2['history'][0]['activity_interval']['valid'], 'first interval of next page retains its predecessor')
        invalid = query(limit=257)
        check(invalid['activity']['activity_pct'] is None and invalid['activity']['coverage_pct'] is None, 'invalid query cannot advertise a measured percentage')
        expired = query(current=8 * 86400)
        check(expired['reason'] == 'outside_retention' and expired['activity']['activity_pct'] is None, 'expired history stays unknown even before a prune')

        if evidence:
            (evidence / 'provenance.json').write_text(json.dumps({
                'source': 'production ac_client_history.c compiled with real json-c and SQLite',
                'inputs': 'controlled test AP telemetry snapshots, not device measurements',
                'generated_at': base, 'checks': checks,
                'definition': 'positive_byte_delta_duration_ratio',
            }, indent=2) + '\n')
        print(f'ok: {checks} activity checks; empty/idle/weighted/gaps/reset/attachment/missing/retention/pagination; real SQLite + production C')


if __name__ == '__main__':
    main()
