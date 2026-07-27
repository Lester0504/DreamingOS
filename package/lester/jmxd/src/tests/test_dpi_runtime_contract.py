#!/usr/bin/env python3
import os
import platform
import sqlite3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT.parent.parent
JMX_ROOT = PACKAGE_ROOT / "jmx" / "src"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run(command: list[str], **kwargs: object) -> None:
    subprocess.run(command, check=True, **kwargs)


def loader_contract(tmp: Path) -> None:
    db_path = tmp / "signatures.db"
    with sqlite3.connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE app (app_id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER);
            CREATE TABLE dpi_rule (
                rule_id INTEGER PRIMARY KEY, app_id INTEGER, proto TEXT,
                direction TEXT, match_type TEXT, pattern_format TEXT,
                pattern_text TEXT, pattern_hex TEXT, offset INTEGER,
                priority INTEGER, pkt_seq INTEGER, enabled INTEGER
            );
            CREATE TABLE dpi_rule_port (
                id INTEGER PRIMARY KEY, rule_id INTEGER,
                min_port INTEGER, max_port INTEGER
            );
            INSERT INTO app VALUES (1001, 'empty', 1), (1002, 'valid', 1);
            INSERT INTO dpi_rule VALUES
                (1,1001,'tcp','original','exact','text','',NULL,-1,10,0,1),
                (2,1002,'tcp','original','exact','text','GET',NULL,0,20,1,1);
            """
        )
    harness = tmp / "loader_contract.c"
    harness.write_text(
        r'''
#include <assert.h>
#include <string.h>
#include "jmx_signature_db.h"
int main(int argc, char **argv) {
    jmx_rule_set_t rules;
    assert(argc == 2);
    memset(&rules, 0, sizeof(rules));
    assert(jmx_load_signature_db(argv[1], &rules) == 0);
    assert(rules.total_rules == 1);
    jmx_rule_set_free(&rules);
    return 0;
}
''',
        encoding="ascii",
    )
    binary = tmp / "loader_contract"
    run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        f"-I{ROOT}", str(ROOT / "jmx_rule.c"),
        str(ROOT / "jmx_signature_db.c"), str(harness), "-lsqlite3",
        "-lcrypto", "-o", str(binary),
    ])
    run([str(binary), str(db_path)])


def ack_parser_contract(tmp: Path) -> None:
    if platform.system() != "Linux":
        print("skip: ACK parser compile test requires Linux netlink UAPI")
        return
    harness = tmp / "ack_contract.c"
    harness.write_text(
        r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "jmx_nl_push.c"
int main(void) {
    const uint32_t seq = 77, version = 9, rules = 53;
    unsigned char frame[NLMSG_SPACE(sizeof(struct af_msg_hdr_local) +
                                    sizeof(struct jmx_nl_rule_status_msg))];
    struct nlmsghdr *nlh = (struct nlmsghdr *)frame;
    struct af_msg_hdr_local *hdr;
    struct jmx_nl_rule_status_msg *status;
    memset(frame, 0, sizeof(frame));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*hdr) + sizeof(*status));
    nlh->nlmsg_seq = seq;
    hdr = (struct af_msg_hdr_local *)NLMSG_DATA(nlh);
    hdr->magic = JMX_NL_MAGIC;
    hdr->len = sizeof(*status);
    status = (struct jmx_nl_rule_status_msg *)(hdr + 1);
    status->action = JMX_NL_ACT_RULE_STATUS;
    status->request_action = JMX_NL_ACT_RULE_VERSION;
    status->version = version;
    status->active_version = version;
    status->active_rules = rules;
    assert(v2_decode_commit_ack(frame, nlh->nlmsg_len, seq, version, rules) == V2_ACK_OK);
    status->active_rules++;
    assert(v2_decode_commit_ack(frame, nlh->nlmsg_len, seq, version, rules) == V2_ACK_NACK);
    return 0;
}
''',
        encoding="ascii",
    )
    binary = tmp / "ack_contract"
    run([
        os.environ.get("CC", "cc"), "-D_DEFAULT_SOURCE", "-std=c11",
        "-Wall", "-Wextra", "-Werror", f"-I{ROOT}", str(harness),
        "-o", str(binary),
    ], cwd=ROOT)
    run([str(binary)])


def source_contracts() -> None:
    main = read(ROOT / "main.c")
    push = read(ROOT / "jmx_nl_push.c")
    api = read(ROOT / "jmx_dreamingwrt_api.c")
    handler = read(JMX_ROOT / "jmx_v2_nl_handler.c")
    conn = read(JMX_ROOT / "jmx_conntrack.c")
    client = read(JMX_ROOT / "jmx_client.c")

    assert "JMX_NL_ACT_RULE_STATUS" in push
    assert "ack->active_version != version" in push
    assert "ack->active_rules != expected_count" in push
    assert "jmx_v2_rules_get_status" in handler
    assert "g_core_runtime.ready = 0" in main
    assert "g_core_runtime.signature_loaded = rc == 0 ? 1 : 0" in main
    assert "if (try_load_signature_db() == 0)" in main
    assert "jmx_core_set_stage(JMX_CORE_STAGE_FAILED)" in main
    assert "jmx_nl_push_chain_rules" in main
    assert "jmx_restore_legacy_snapshot" in main
    assert "started_mono_ms" in main
    assert "uptime_ms / 1000" in main
    assert "spin_lock_bh(&af_conn_lock)" in conn
    assert "void af_conn_record_match" in conn
    assert "af_conn_record_match(flow->src" in read(JMX_ROOT / "jmx_main.c")
    assert "hlist_entry((struct hlist_node *)v, af_conn_t, node)" in conn
    assert "seq_release_private" in conn
    assert client.count("cur_timep >= info->latest_time &&") == 2
    assert '"kernel_classified_apps"' in api
    assert '"host_inferred_apps"' in api
    assert '"classification_source"' in api
    assert '"kernel_dpi"' in api
    assert '"host_signature_inference"' in api
    assert '"classification_sample_window_seconds"' in api
    assert '"classification_new_flows_only"' in api
    assert '"classification_generation_replay"' in api


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="jmx-dpi-contract-") as temp:
        tmp = Path(temp)
        loader_contract(tmp)
        ack_parser_contract(tmp)
    source_contracts()
    print("ok: DPI v3 transaction, VERSION STATUS ACK, READY, iterator, and clock contracts")


if __name__ == "__main__":
    main()
