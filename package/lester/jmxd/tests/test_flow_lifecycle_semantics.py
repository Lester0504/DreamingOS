#!/usr/bin/env python3
import sqlite3
import tempfile

SCHEMA = """
CREATE TABLE audit_flow_sample (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, flow_id TEXT, protocol TEXT, source_ip TEXT,
  destination_ip TEXT, source_port INTEGER, destination_port INTEGER, client_ip TEXT, client_mac TEXT,
  remote_ip TEXT, tx_bytes INTEGER, rx_bytes INTEGER, source TEXT DEFAULT 'nf_conntrack_sample'
);
CREATE TABLE audit_flow_lifecycle (
  flow_id TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, last_sample_ts INTEGER,
  sample_count INTEGER, protocol TEXT, source_ip TEXT, destination_ip TEXT, source_port INTEGER,
  destination_port INTEGER, client_ip TEXT, client_mac TEXT, remote_ip TEXT, tx_bytes INTEGER,
  rx_bytes INTEGER, active INTEGER, source TEXT DEFAULT 'nf_conntrack_lifecycle'
);
CREATE TABLE audit_flow_event_lifecycle (
  flow_id TEXT PRIMARY KEY, flow_key TEXT DEFAULT '', first_seen INTEGER, last_seen INTEGER,
  destroy_ts INTEGER, event_count INTEGER, protocol TEXT, src_ip TEXT, dst_ip TEXT,
  source_ip TEXT, destination_ip TEXT, source_port INTEGER, destination_port INTEGER,
  client_ip TEXT, client_mac TEXT, remote_ip TEXT, orig_packets INTEGER, repl_packets INTEGER,
  orig_bytes INTEGER, repl_bytes INTEGER, tx_bytes INTEGER, rx_bytes INTEGER, source TEXT DEFAULT 'ctnetlink_destroy',
  exact_lifecycle INTEGER DEFAULT 1, byte_accounting_exact INTEGER DEFAULT 1,
  byte_counter_valid INTEGER DEFAULT 1, byte_counter_reason TEXT DEFAULT '',
  policy_id TEXT DEFAULT '', policy_hit INTEGER DEFAULT 0, policy_mark INTEGER DEFAULT 0,
  route_rule_prio INTEGER DEFAULT 0, route_wan_id INTEGER DEFAULT 0,
  reply_src_ip TEXT DEFAULT '', reply_dst_ip TEXT DEFAULT '', reply_src_port INTEGER DEFAULT 0,
  reply_dst_port INTEGER DEFAULT 0, snat_ip TEXT DEFAULT '', dnat_ip TEXT DEFAULT '',
  snat_port INTEGER DEFAULT 0, dnat_port INTEGER DEFAULT 0
);
"""

def choose_mode(db, start, end, requested="auto"):
    if requested in ("event_lifecycle", "flow_event_lifecycle", "ctnetlink_lifecycle", "exact_lifecycle"):
        return "event_lifecycle"
    if requested in ("lifecycle", "flow_lifecycle"):
        return "lifecycle"
    rows = db.execute(
        "SELECT COUNT(*) FROM audit_flow_event_lifecycle WHERE destroy_ts>=? AND destroy_ts<=?",
        (start, end),
    ).fetchone()[0]
    return "event_lifecycle" if rows else "lifecycle"

def summary(db, start, end, requested="auto"):
    mode = choose_mode(db, start, end, requested)
    if mode == "event_lifecycle":
        total, exact_life, exact_bytes, policy_rows, nat_rows = db.execute(
            "SELECT COUNT(*),"
            "SUM(CASE WHEN COALESCE(exact_lifecycle,0)!=0 THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN COALESCE(byte_accounting_exact,0)!=0 AND COALESCE(byte_counter_valid,0)!=0 THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN COALESCE(policy_hit,0)!=0 AND (COALESCE(policy_mark,0)!=0 OR COALESCE(route_rule_prio,0)>0 OR COALESCE(route_wan_id,0)>0 OR COALESCE(policy_id,'')<>'') THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN COALESCE(snat_ip,'')<>'' OR COALESCE(dnat_ip,'')<>'' OR COALESCE(snat_port,0)>0 OR COALESCE(dnat_port,0)>0 THEN 1 ELSE 0 END) "
            "FROM audit_flow_event_lifecycle WHERE destroy_ts>=? AND destroy_ts<=?",
            (start, end),
        ).fetchone()
        return {
            "mode": mode,
            "total": total,
            "exact_lifecycle": total > 0 and exact_life == total,
            "byte_accounting_exact": total > 0 and exact_bytes == total,
            "exact_window_bytes": total > 0 and exact_bytes == total,
            "policy_supported": policy_rows > 0,
            "policy_hit_rows": policy_rows,
            "nat_tuple_supported": nat_rows > 0,
            "nat_tuple_rows": nat_rows,
            "degraded": False,
        }
    total = db.execute(
        "SELECT COUNT(*) FROM audit_flow_lifecycle WHERE last_seen>=? AND last_seen<=?",
        (start, end),
    ).fetchone()[0]
    return {
        "mode": mode,
        "total": total,
        "exact_lifecycle": False,
        "byte_accounting_exact": False,
        "exact_window_bytes": False,
        "policy_supported": False,
        "policy_hit_rows": 0,
        "nat_tuple_supported": False,
        "nat_tuple_rows": 0,
        "degraded": True,
    }

def main():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)
    db.execute(
        "INSERT INTO audit_flow_event_lifecycle "
        "(flow_id,first_seen,last_seen,destroy_ts,event_count,protocol,source_ip,destination_ip,source_port,destination_port,"
        "client_ip,client_mac,remote_ip,orig_packets,repl_packets,orig_bytes,repl_bytes,tx_bytes,rx_bytes,"
        "exact_lifecycle,byte_accounting_exact,byte_counter_valid,byte_counter_reason,policy_id,policy_hit,policy_mark,route_rule_prio,route_wan_id,reply_src_ip,reply_dst_ip,snat_ip,dnat_ip) "
        "VALUES ('exact1',100,130,131,3,'tcp','192.168.1.9','93.184.216.34',53000,443,'192.168.1.9',"
        "'aa:bb:cc:dd:ee:ff','93.184.216.34',10,12,1000,2000,1000,2000,1,1,1,'ctnetlink_destroy_counters',"
        "'rule-100',1,6553601,100,1,'93.184.216.34','198.51.100.7','198.51.100.7','')"
    )
    db.execute(
        "INSERT INTO audit_flow_event_lifecycle "
        "(flow_id,first_seen,last_seen,destroy_ts,event_count,protocol,source_ip,destination_ip,source_port,destination_port,"
        "client_ip,remote_ip,orig_bytes,repl_bytes,tx_bytes,rx_bytes,exact_lifecycle,byte_accounting_exact,byte_counter_valid,byte_counter_reason,dnat_ip) "
        "VALUES ('dnat-no-bytes',200,220,221,2,'tcp','203.0.113.8','198.51.100.9',51000,8443,'192.168.1.20',"
        "'203.0.113.8',0,0,0,0,1,0,0,'ctnetlink_destroy_no_counter_attrs','192.168.1.20')"
    )
    db.execute(
        "INSERT INTO audit_flow_lifecycle "
        "(flow_id,first_seen,last_seen,last_sample_ts,sample_count,protocol,source_ip,destination_ip,source_port,destination_port,client_ip,client_mac,remote_ip,tx_bytes,rx_bytes,active) "
        "VALUES ('sample1',300,360,360,2,'udp','192.168.1.9','8.8.8.8',53001,53,'192.168.1.9','aa:bb:cc:dd:ee:ff','8.8.8.8',50,60,1)"
    )
    s = summary(db, 90, 150)
    assert s["mode"] == "event_lifecycle" and s["total"] == 1 and s["exact_lifecycle"] is True, s
    assert s["byte_accounting_exact"] is True and s["exact_window_bytes"] is True, s
    assert s["policy_supported"] is True and s["policy_hit_rows"] == 1, s
    assert s["nat_tuple_supported"] is True and s["nat_tuple_rows"] == 1, s
    s = summary(db, 190, 230)
    assert s["mode"] == "event_lifecycle" and s["total"] == 1 and s["exact_lifecycle"] is True, s
    assert s["byte_accounting_exact"] is False and s["exact_window_bytes"] is False and s["degraded"] is False, s
    assert s["policy_supported"] is False and s["policy_hit_rows"] == 0, s
    assert s["nat_tuple_supported"] is True and s["nat_tuple_rows"] == 1, s
    dnat = db.execute("SELECT dnat_ip, byte_counter_valid, byte_accounting_exact FROM audit_flow_event_lifecycle WHERE flow_id='dnat-no-bytes'").fetchone()
    assert dnat == ("192.168.1.20", 0, 0), dnat
    s = summary(db, 300, 370)
    assert s["mode"] == "lifecycle" and s["total"] == 1 and s["degraded"] is True, s
    assert s["exact_lifecycle"] is False and s["byte_accounting_exact"] is False and s["exact_window_bytes"] is False, s
    assert s["policy_supported"] is False and s["nat_tuple_supported"] is False, s
    print("ok: exact event lifecycle preferred; sampled fallback degraded; DNAT no-byte row is not marked exact bytes")

if __name__ == "__main__":
    main()
