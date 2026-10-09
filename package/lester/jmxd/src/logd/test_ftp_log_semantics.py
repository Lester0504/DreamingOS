#!/usr/bin/env python3
"""vsftpd native syslog grammar, source boundaries and semantic presentation."""
import json
import subprocess
import tempfile
from pathlib import Path

from test_log_event_semantics import c_function, COLLECTORS, EVENT_SEMANTICS, ROOT


def build_classifier(out):
    source = COLLECTORS.read_text()
    harness = r'''
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <json-c/json.h>
#include "event_semantics.h"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static const char *logd_json_str(struct json_object *o,const char *k,const char *fallback) {
 struct json_object *v=NULL;
 return json_object_object_get_ex(o,k,&v) && json_object_is_type(v,json_type_string) ? json_object_get_string(v) : fallback;
}
static int logd_contains_ci(const char *s,const char *needle) {
 for (; *s; s++) if (!strncasecmp(s,needle,strlen(needle))) return 1;
 return 0;
}
'''
    harness += '\n'.join(c_function(source, name) for name in (
        'static void logd_auth_detail_token(', 'static int logd_business_line(',
        'static int logd_ftp_line(', 'static void logd_line_classify('))
    harness += r'''
int main(int argc,char **argv) {
 if(argc!=4) return 2;
 struct json_object *detail=json_object_new_object(),*event=json_object_new_object();
 const char *category,*id;
 logd_line_classify(argv[3],atoi(argv[2]),argv[1],"ftp",&category,&id,detail);
 json_object_object_add(event,"event",json_object_new_string(id));
 json_object_object_add(event,"category",json_object_new_string(category));
 json_object_object_add(event,"detail_json",detail);
 json_object_object_add(event,"domain",json_object_new_string(dw_event_domain(category,id,detail)));
 json_object_object_add(event,"business",json_object_new_boolean(dw_event_is_business(id)));
 json_object_object_add(event,"severity",json_object_new_string(dw_event_effective_severity(id,detail,"info")));
 json_object_object_add(event,"zh",dw_event_presentation_render(event,"zh-CN"));
 json_object_object_add(event,"en",dw_event_presentation_render(event,"en"));
 puts(json_object_to_json_string_ext(event,JSON_C_TO_STRING_PLAIN));
 json_object_put(event); return 0;
}
'''
    c = out / 'classifier.c'
    binary = out / 'classifier'
    c.write_text(harness)
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c'], text=True).split()
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'src'),
                    str(c), str(EVENT_SEMANTICS), *flags, '-o', str(binary)], check=True)
    return binary


def classify(binary, line, program='vsftpd', kernel=0):
    return json.loads(subprocess.check_output([str(binary), program, str(kernel), line], text=True))


def test_ftp_native_log_semantics():
    with tempfile.TemporaryDirectory(prefix='ftp-log-') as tmp:
        binary = build_classifier(Path(tmp))
        count = 0
        for action in ('LOGIN', 'UPLOAD', 'DOWNLOAD', 'MKDIR', 'DELETE', 'RENAME', 'RMDIR', 'CHMOD'):
            for ok in (True, False):
                result = 'OK' if ok else 'FAIL'
                line = f'[alice] {result} {action}: Client "2001:db8::7"'
                if action != 'LOGIN':
                    line += ', "/shared/有空格的 file.txt"'
                if action in ('UPLOAD', 'DOWNLOAD'):
                    line += ', 1024 bytes, 0.50Kbyte/sec'
                row = classify(binary, line)
                detail = row['detail_json']
                assert row['business']
                assert row['domain'] == ('AUTH' if action == 'LOGIN' else 'FILES'), row
                assert detail['result'] == ('success' if ok else 'failed'), row
                assert detail['username'] == 'alice' and detail['source_ip'] == '2001:db8::7'
                assert detail['protocol'] == 'ftp'
                assert ('actor' in detail) == (ok or action != 'LOGIN')
                assert 'duration' not in detail and 'failure_reason' not in detail
                assert row['severity'] == ('info' if ok else 'warning' if action == 'LOGIN' else 'error')
                assert ('成功' if ok else '失败') in row['zh']['description']
                assert ('succeeded' if ok else 'failed') in row['en']['description']
                if not ok:
                    assert '未记录' in row['zh']['description']
                    assert row['zh']['render_status'] == 'partial'
                if action in ('UPLOAD', 'DOWNLOAD'):
                    assert detail['size_bytes'] == 1024 and detail['rate_kib_s'] == 0.5
                if action in ('RENAME', 'CHMOD'):
                    assert 'path' not in detail and 'operation_args' in detail
                    assert row['zh']['render_status'] == 'partial'
                count += 1
        for tail in ('0.00Kbyte/sec', '512 bytes, 7.30Kbyte/sec'):
            line = '[bob] OK DOWNLOAD: Client "192.0.2.1", "/a \\"quoted\\" file", ' + tail
            row = classify(binary, line)
            assert row['detail_json']['size_bytes'] == (0 if tail.startswith('0.') else 512)
            assert row['detail_json']['path'] == '/a \\"quoted\\" file'
            count += 1
        row = classify(binary, 'FAIL UPLOAD: Client "192.0.2.1", 0.00Kbyte/sec')
        assert row['event'] == 'FTP_TRANSFER_FINISHED' and 'username' not in row['detail_json']
        assert row['zh']['render_status'] == 'partial'
        count += 1
        connect = 'CONNECT: Client "192.0.2.1"'
        row = classify(binary, connect)
        assert row['event'] == 'FTP_CONNECTION' and row['detail_json']['result'] == 'connected'
        assert '尚未完成认证' in row['zh']['description'] and row['severity'] == 'info'
        count += 1
        for reason in ('too many sessions.', 'too many sessions for this address.', 'tcp_wrappers denial.'):
            row = classify(binary, connect + ', "Connection refused: ' + reason + '"')
            assert row['detail_json']['result'] == 'refused' and row['severity'] == 'warning'
            assert row['detail_json']['failure_reason'].endswith(reason)
            count += 1
        invalid = [
            'OK CONNECT: Client "192.0.2.1"', 'LOGIN: Client "192.0.2.1"',
            'CONNECT: Client "192.0.2.1", "random reason"',
            '[alice] OK DOWNLOAD: Client "192.0.2.1", "/x", -1 bytes, 1.00Kbyte/sec',
            '[alice] OK DOWNLOAD: Client "192.0.2.1", "/x", 9223372036854775808 bytes, 1.00Kbyte/sec',
            '[alice] OK DOWNLOAD: Client "192.0.2.1", "/x", 1 bytes, NaNKbyte/sec',
            '[alice] OK DOWNLOAD: Client "192.0.2.1", "/x", 1 bytes, 1.00Kbyte/sec junk',
            '[alice] OK DELETE: Client "192.0.2.1", "/x" trailing',
            '[alice] OK DOWNLOAD: Client "192.0.2.1", "/x", 1 bytes',
            '[alice] OK LOGIN: Client "192.0.2.1", anon password "do-not-import"',
            '[alice] FTP response: Client "192.0.2.1", "226 Transfer complete"',
            '[alice] FTP command: Client "192.0.2.1", "STOR /x"',
        ]
        for line in invalid:
            row = classify(binary, line)
            assert row['event'] == 'log_line' and row['detail_json'] == {}, row
            count += 1
        for program, kernel in (('other-app', 0), ('vsftpd-wrapper', 0), ('vsftpd', 1)):
            row = classify(binary, '[alice] OK LOGIN: Client "192.0.2.1"', program, kernel)
            assert row['event'] == 'log_line' and not row['business'], row
            count += 1
        print(f'{count} FTP source/semantics cases passed')


if __name__ == '__main__':
    test_ftp_native_log_semantics()
