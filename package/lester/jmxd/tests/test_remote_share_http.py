#!/usr/bin/env python3
"""Real webd -> ubus -> core file-service checks in the isolated QEMU fixture.

The fixture starts the production binaries against a temporary config directory
and seeds temporary app tokens for each role. No production router is contacted.
"""
import ftplib
import http.client
import io
import json
import os
from pathlib import Path
import sqlite3
import time

BASE = Path('/tmp/remote-share-http')
assert 'root=/dev/vda' in Path('/proc/cmdline').read_text()
assert (BASE / '.fixture').read_text().strip() == 'isolated-remote-share-http-qemu'
assert os.path.ismount('/etc/dreamingwrt')
RESULTS = []
CHECKS = []
PASSWORD = 'Http-share-fixture-1005'
PREFIX = '/api/v1/services'


def request(method, path, body=None, role='owner', status=200, error=None):
    conn = http.client.HTTPConnection('127.0.0.1', 19490, timeout=100)
    headers = {'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin'}
    if role:
        headers['Authorization'] = 'Bearer isolated-share-http-' + role
    conn.request(method, path, None if body is None else json.dumps(body), headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    value = json.loads(raw)
    data = value.get('data', value)
    actual_error = data.get('error', value.get('error'))
    if isinstance(actual_error, dict):
        actual_error = actual_error.get('code')
    row = {'method': method, 'path': path, 'role': role, 'status': response.status,
           'code': value.get('code'), 'error': actual_error}
    RESULTS.append(row)
    (BASE / 'evidence/requests.json').write_text(json.dumps(RESULTS, indent=2))
    assert response.status == status, (row, value)
    if error is not None:
        assert actual_error == error, (row, value)
    if status == 200:
        assert value.get('code') == 2000, (row, value)
    return data


def passed(name):
    CHECKS.append(name)
    print(json.dumps({'passed': name}), flush=True)


def ftp():
    return request('GET', PREFIX + '/ftp')


def account(aid):
    return next(x for x in request('GET', PREFIX + '/file-sharing/accounts')['items'] if x['id'] == aid)


def share(sid):
    return next(x for x in ftp()['shares'] if x['id'] == sid)


def action(name):
    return request('POST', PREFIX + '/ftp/actions', {'confirm': True, 'expected_revision': ftp()['control_revision'], 'action': name}, role='admin')


def snapshot():
    with sqlite3.connect('/etc/dreamingwrt/config.db') as db:
        names = [x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'ftp_%' OR name LIKE 'file_%') ORDER BY name")]
        return {name: db.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall() for name in names}


def run():
    services = ['samba', 'nfs', 'webdav', 'ftp', 'sftp', 'dlna', 'afp']
    for role in ['owner', 'viewer']:
        for service in services:
            request('GET', PREFIX + '/' + service, role=role)
        for path in [PREFIX + '/file-sharing/accounts', PREFIX + '/file-sharing/operations', '/api/v1/storage/file-services']:
            request('GET', path, role=role)
    passed('real_HTTP_reads_reach_registered_core_handlers')
    before = snapshot()
    request('GET', PREFIX + '/ftp', role=None, status=401)
    request('PUT', PREFIX + '/ftp', {'confirm': True}, role=None, status=401)
    request('GET', PREFIX + '/ftp', role='invalid', status=401)
    writes = [('PUT', '/ftp'), ('POST', '/ftp/shares'), ('PUT', '/ftp/shares/ftp-http-missing'),
              ('DELETE', '/ftp/shares/ftp-http-missing'), ('POST', '/ftp/actions'),
              ('POST', '/file-sharing/operations'), ('POST', '/file-sharing/operations/http-permission-1005/retry'),
              ('POST', '/file-sharing/accounts'), ('PUT', '/file-sharing/accounts/account-http-missing'),
              ('DELETE', '/file-sharing/accounts/account-http-missing')]
    for role in ['viewer', 'operator', 'ai-agent']:
        for method, path in writes:
            request(method, PREFIX + path, {'confirm': True, 'expected_revision': 1}, role=role, status=403)
    for method, path in writes[-3:]:
        request(method, PREFIX + path, {'confirm': True, 'expected_revision': 1}, role='admin', status=403)
    for service, collection in [('samba', 'shares'), ('nfs', 'exports'), ('webdav', 'shares')]:
        for method, tail in [('PUT', ''), ('POST', '/actions'), ('POST', '/' + collection), ('PUT', '/' + collection + '/http-missing'), ('DELETE', '/' + collection + '/http-missing')]:
            request(method, PREFIX + '/' + service + tail, {'confirm': True, 'expected_revision': 1}, role='viewer', status=403)
    assert snapshot() == before, 'Rejected HTTP requests changed file-service configuration'
    passed('anonymous_invalid_token_and_role_matrix_reject_without_config_changes')

    for method, path in [('POST', '/ftp/shares'), ('POST', '/ftp/actions'), ('POST', '/file-sharing/accounts'), ('POST', '/file-sharing/operations')]:
        request(method, PREFIX + path, {}, status=409, error='confirmation_required')
    request('PUT', PREFIX + '/ftp', {}, status=400, error='confirmation_required')
    request('PUT', PREFIX + '/ftp', {'confirm': True}, status=422, error='missing_expected_revision')
    request('POST', PREFIX + '/ftp/actions', {'confirm': True, 'action': 'start'}, status=422, error='missing_expected_revision')
    assert snapshot() == before
    passed('HTTP_confirmation_and_revision_guards_preserve_configuration')

    created = request('POST', PREFIX + '/file-sharing/accounts', {'confirm': True, 'username': 'httpftp', 'password': PASSWORD})
    aid = created['id']
    acct = account(aid)
    assert acct['has_password'] and PASSWORD not in json.dumps(acct)
    action('stop')
    old = ftp()
    configured = request('PUT', PREFIX + '/ftp', {'confirm': True, 'expected_revision': old['revision'],
        'listen_address': '127.0.0.1', 'listen_port': 2121, 'passive_min_port': 22000, 'passive_max_port': 22004,
        'passive_address': '', 'tls': False, 'cert_file': '', 'key_file': ''}, role='admin')
    assert configured['revision'] == old['revision'] + 1 and not configured['running'] and not configured['requested_running']
    request('PUT', PREFIX + '/ftp', {'confirm': True, 'expected_revision': old['revision'], 'listen_port': 2122}, role='admin', status=409, error='revision_conflict')
    assert ftp()['settings']['listen_port'] == 2121
    directory = BASE / 'data'
    directory.mkdir(exist_ok=True)
    os.chown(directory, 0, 65534)
    os.chmod(directory, 0o770)
    spec = {'confirm': True, 'name': 'http-files', 'path': str(directory), 'enabled': True, 'read_only': False,
            'users': [{'account_id': aid, 'read_only': False}], 'note': 'HTTP fixture'}
    created = request('POST', PREFIX + '/ftp/shares', spec, role='admin')
    sid = created['id']
    initial = share(sid)
    assert initial['name'] == 'http-files' and initial['users'][0]['account_id'] == aid
    request('PUT', PREFIX + '/ftp/shares/' + sid, {'confirm': True, 'expected_revision': initial['revision'], 'note': 'HTTP updated'}, role='admin')
    request('PUT', PREFIX + '/ftp/shares/' + sid, {'confirm': True, 'expected_revision': initial['revision'], 'note': 'stale'}, role='admin', status=409, error='revision_conflict')
    assert share(sid)['note'] == 'HTTP updated'
    request('DELETE', PREFIX + '/ftp/shares/' + sid, status=409, error='confirmation_required')
    request('DELETE', PREFIX + '/ftp/shares/' + sid, {'confirm': True}, status=422, error='missing_expected_revision')
    passed('owner_account_and_admin_settings_share_CRUD_with_canonical_readback')

    started = action('start')
    assert started['running'] and started['requested_running']
    payload = b'Real HTTP -> core -> FTP runtime\x00\xff\n'
    with ftplib.FTP() as client:
        client.connect('127.0.0.1', 2121, timeout=20)
        client.login(acct['login'], PASSWORD)
        client.cwd('http-files')
        client.storbinary('STOR http-roundtrip.bin', io.BytesIO(payload))
        result = io.BytesIO()
        client.retrbinary('RETR http-roundtrip.bin', result.write)
        assert result.getvalue() == payload
    stopped = action('stop')
    assert not stopped['running'] and not stopped['requested_running']
    enabled = action('enable')
    assert enabled['enabled'] and not enabled['running'] and not enabled['requested_running']
    disabled = action('disable')
    assert not disabled['enabled'] and not disabled['running']
    request('POST', PREFIX + '/ftp/actions', {'confirm': True, 'expected_revision': started['control_revision'], 'action': 'start'}, role='admin', status=409, error='revision_conflict')
    assert not ftp()['running']
    passed('HTTP_service_actions_apply_real_FTP_transfer_and_keep_autostart_separate')

    request('DELETE', PREFIX + '/file-sharing/accounts/' + aid, {'confirm': True, 'expected_revision': acct['revision']}, status=400, error='account_in_use')
    request('PUT', PREFIX + '/file-sharing/accounts/' + aid, {'confirm': True, 'expected_revision': acct['revision'], 'label': 'HTTP account updated'})
    request('PUT', PREFIX + '/file-sharing/accounts/' + aid, {'confirm': True, 'expected_revision': acct['revision'], 'label': 'stale'}, status=409, error='revision_conflict')
    assert account(aid)['label'] == 'HTTP account updated'
    passed('account_reference_and_revision_errors_survive_HTTP_ubus_path')

    opid = 'http-share-operation-20261005'
    operation = {'confirm': True, 'request_id': opid, 'items': [{'protocol': 'ftp', 'action': 'create', 'body': {
        'name': 'http-receipt', 'path': str(directory), 'read_only': True, 'users': [{'account_id': aid, 'read_only': True}]}}]}
    receipt = request('POST', PREFIX + '/file-sharing/operations', operation, role='admin')
    assert receipt['state'] == 'success'
    repeated = request('POST', PREFIX + '/file-sharing/operations', operation, role='admin')
    assert repeated['results'] == receipt['results']
    assert request('GET', PREFIX + '/file-sharing/operations/' + opid, role='viewer')['results'] == receipt['results']
    second = receipt['results'][0]['result']['id']
    assert len([x for x in ftp()['shares'] if x['name'] == 'http-receipt']) == 1
    passed('HTTP_operation_receipt_readback_and_idempotent_repeat')

    current = ftp()
    with sqlite3.connect('/etc/dreamingwrt/config.db', timeout=1) as writer:
        writer.execute('BEGIN IMMEDIATE')
        assert ftp()['revision'] == current['revision']
        request('PUT', PREFIX + '/ftp', {'confirm': True, 'expected_revision': current['revision'], 'listen_port': 2122}, role='admin', status=400, error='storage_busy')
        writer.rollback()
    assert ftp()['revision'] == current['revision']
    passed('real_SQLite_contention_HTTP_read_stays_available_and_write_reports_busy')

    for item in [sid, second]:
        record = share(item)
        request('DELETE', PREFIX + '/ftp/shares/' + item, {'confirm': True, 'expected_revision': record['revision']}, role='admin')
    request('DELETE', PREFIX + '/file-sharing/accounts/' + aid, {'confirm': True, 'expected_revision': account(aid)['revision']})
    assert not ftp()['shares'] and not request('GET', PREFIX + '/file-sharing/accounts')['items']
    assert (directory / 'http-roundtrip.bin').read_bytes() == payload
    request('PUT', PREFIX + '/ftp/shares/ftp-http-missing', {'confirm': True, 'expected_revision': 1, 'note': 'absent'}, role='admin', status=404, error='not_found')
    request('GET', PREFIX + '/ftp/shares', status=405, error='method_not_allowed')
    passed('HTTP_delete_preserves_data_releases_accounts_and_missing_routes_report_truthfully')
    result = {'result': 'PASS', 'request_count': len(RESULTS), 'checks': CHECKS,
              'environment': 'isolated QEMU; actual webd/ubus/core and production FTP init/PAM; temporary app tokens'}
    (BASE / 'evidence/result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    run()
