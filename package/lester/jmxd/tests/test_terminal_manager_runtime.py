#!/usr/bin/env python3
"""Exercise the real C runtime over its Unix protocol; all state is under /tmp.

TM_BINARY must name a native TM_TESTING build. The optional SSH tests use a
separate unprivileged sshd, generated fixture keys and a temporary directory.
No device service, production account or source tree configuration is changed.
"""
import array
import base64
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import threading
import sqlite3
import unittest
from urllib.parse import unquote


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("channel closed")
        result.extend(chunk)
    return bytes(result)


class WS:
    def __init__(self, peer):
        self.peer = peer
        self.peer.settimeout(8)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(exact(peer, 1))
        assert b"101 Switching Protocols" in header

    def event(self):
        head = exact(self.peer, 2)
        size = head[1] & 127
        if size == 126:
            size = struct.unpack("!H", exact(self.peer, 2))[0]
        elif size == 127:
            size = struct.unpack("!Q", exact(self.peer, 8))[0]
        data = exact(self.peer, size)
        return (head[0] & 15, json.loads(data) if head[0] & 15 == 1 else data)

    def send(self, value, opcode=1, final=True):
        data = json.dumps(value, ensure_ascii=False).encode() if isinstance(value, dict) else value
        mask = os.urandom(4)
        header = bytes([(128 if final else 0) | opcode])
        if len(data) < 126:
            header += bytes([128 | len(data)])
        else:
            header += bytes([128 | 126]) + struct.pack("!H", len(data))
        self.peer.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(data)))

    def until_state(self, name):
        for _ in range(100):
            opcode, data = self.event()
            if opcode == 1 and data.get("state") == name:
                return data
        raise AssertionError("state not received: " + name)


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tm-runtime-test-")
        cls.home = Path(cls.temp.name)
        cls.socket = str(cls.home / "runtime.sock")
        (cls.home / "secret.key").write_bytes(os.urandom(32))
        cls.log = (cls.home / "runtime.log").open("wb")
        cls.process = subprocess.Popen([os.environ["TM_BINARY"], "--socket", cls.socket, "--store", str(cls.home / "state.db"), "--key", str(cls.home / "secret.key"), "--spool", str(cls.home / "spool")], stdout=cls.log, stderr=cls.log)
        for _ in range(100):
            if Path(cls.socket).exists():
                break
            time.sleep(.05)
        else:
            raise RuntimeError("runtime failed to start")
        cls.sshd = None
        if os.environ.get("TM_TEST_SSHD"):
            cls.start_sshd()

    @classmethod
    def start_sshd(cls):
        cls.user = pwd.getpwuid(os.getuid()).pw_name
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "fixture-passphrase", "-f", str(cls.home / "client")], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.home / "host")], check=True)
        shutil.copyfile(cls.home / "client.pub", cls.home / "authorized_keys")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        config = f"Port {cls.port}\nListenAddress 127.0.0.1\nHostKey {cls.home}/host\nPidFile {cls.home}/sshd.pid\nAuthorizedKeysFile {cls.home}/authorized_keys\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAllowUsers {cls.user}\nSubsystem sftp internal-sftp\nLogLevel ERROR\n"
        (cls.home / "sshd.conf").write_text(config)
        cls.sshlog = (cls.home / "sshd.log").open("wb")
        cls.sshd = subprocess.Popen([os.environ["TM_TEST_SSHD"], "-D", "-e", "-f", str(cls.home / "sshd.conf")], stdout=cls.sshlog, stderr=cls.sshlog)
        time.sleep(.4)
        if cls.sshd.poll() is not None:
            raise RuntimeError((cls.home / "sshd.log").read_text())

    @classmethod
    def tearDownClass(cls):
        if cls.sshd:
            cls.sshd.terminate()
            cls.sshd.wait(timeout=5)
            cls.sshlog.close()
        cls.process.terminate()
        cls.process.wait(timeout=15)
        cls.log.close()
        cls.temp.cleanup()

    def rpc(self, path, method="GET", body=None, owner="test-owner", manage=True, passed=None):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(12)
            client.connect(self.socket)
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [passed.fileno()]))] if passed else []
            client.sendmsg([b"F" if passed else b"J"], ancillary)
            data = json.dumps(dict(path=path, method=method, body=body or {}, owner=owner, manage=manage)).encode()
            client.sendall(struct.pack("!I", len(data)) + data)
            return json.loads(exact(client, struct.unpack("!I", exact(client, 4))[0]))

    def start(self, host, auth=None):
        response = self.rpc("sessions", "POST", dict(host=host, auth=auth or {}, workspace_id="test-workspace"))
        self.assertEqual(response["status"], 202, response)
        session = response["data"]
        a, b = socket.socketpair()
        result = self.rpc(f"sessions/{session['id']}/ws", body={"websocket_key": base64.b64encode(os.urandom(16)).decode()}, passed=a)
        a.close()
        self.assertTrue(result["data"]["fd_owned"])
        ws = WS(b)
        self.addCleanup(ws.peer.close)
        self.addCleanup(lambda: self.rpc(f"sessions/{session['id']}/disconnect", "POST"))
        return session, ws

    def test_01_store_isolation_cas_and_group_delete(self):
        group = self.rpc("groups", "POST", {"name": "实验组", "order": 1})["data"]
        host = self.rpc("hosts", "POST", {"name": "主机 A", "type": "ssh", "address": "::1", "username": "operator", "group_id": group["id"], "auth": {"type": "password", "password": "fixture-only-password"}})["data"]
        self.assertTrue(host["credential_configured"])
        self.assertNotIn("fixture-only-password", json.dumps(host))
        self.assertNotIn("auth", host)
        self.assertEqual(self.rpc("hosts/" + host["id"], owner="another")["status"], 404)
        changed = self.rpc("hosts/" + host["id"], "PATCH", {"name": "renamed", "revision": host["revision"]})
        self.assertEqual(changed["status"], 200)
        self.assertTrue(changed["data"]["credential_configured"])
        self.assertEqual(self.rpc("hosts/" + host["id"], "PATCH", {"name": "lost", "revision": host["revision"]})["status"], 409)
        self.assertEqual(self.rpc("groups/" + group["id"], "DELETE", {"revision": group["revision"]})["status"], 200)
        self.assertEqual(self.rpc("hosts/" + host["id"])["data"]["group_id"], "")
        self.assertEqual(self.rpc("sessions", "POST", {}, manage=False)["status"], 403)
        self.assertEqual(self.rpc("capabilities", manage=False)["data"]["permissions"]["connect"], False)
        database = (self.home / "state.db").read_bytes() + (self.home / "state.db-wal").read_bytes()
        self.assertNotIn(b"fixture-only-password", database)

    def test_02_preferences_conflict(self):
        prefs = self.rpc("preferences")["data"]
        update = self.rpc("preferences", "PUT", {**prefs, "font_size": 18})
        self.assertEqual(update["status"], 200)
        self.assertEqual(self.rpc("preferences", "PUT", {**prefs, "font_size": 22})["status"], 409)
        self.assertEqual(self.rpc("preferences")["data"]["font_size"], 18)

    def test_03_real_pty_unicode_fragmentation_and_isolation(self):
        session, ws = self.start({"type": "local", "name": "local test"})
        ws.until_state("ready")
        self.assertEqual(self.rpc("sessions/" + session["id"], owner="another")["status"], 404)
        command = json.dumps({"type": "input", "data": "printf '\\344\\270\\255\\346\\226\\207\\345\\215\\217\\350\\256\\256\\346\\210\\220\\345\\212\\237\\n'\n"}, ensure_ascii=False).encode()
        ws.send(command[:10], final=False)
        ws.send(command[10:], opcode=0)
        output = b""
        for _ in range(30):
            opcode, data = ws.event()
            if opcode == 2:
                output += data
                if "中文协议成功".encode() in output:
                    break
        self.assertIn("中文协议成功".encode(), output)
        ws.send({"type": "resize", "cols": 91, "rows": 27})
        sample = self.rpc(f"sessions/{session['id']}/system-info")
        self.assertEqual(sample["status"], 200, sample)
        self.assertIsNone(sample["data"]["cpu_percent"])
        sample2 = self.rpc(f"sessions/{session['id']}/processes")
        self.assertEqual(sample2["status"], 200)
        self.assertTrue(sample2["data"]["items"])
        self.assertEqual(self.rpc(f"sessions/{session['id']}/files", body={"path": "/"})["status"], 422)

    def test_04_ssh_sftp_and_transfer(self):
        if not self.sshd:
            self.skipTest("isolated sshd not configured")
        session, ws = self.start({"type": "ssh", "name": "ssh fixture", "address": "127.0.0.1", "port": self.port, "username": self.user}, {"type": "key", "private_key": (self.home / "client").read_text(), "passphrase": "fixture-passphrase"})
        pending = ws.until_state("host_key_confirmation_required")
        self.assertEqual(self.rpc(f"sessions/{session['id']}/trust", "POST", {"fingerprint": pending["fingerprint"]})["status"], 200)
        ready = ws.until_state("ready")
        self.assertTrue(ready["capabilities"]["sftp"])
        self.assertEqual(ready["cwd_source"], "sftp_home")
        path = str(self.home / "中文 space ' quote")
        base = f"sessions/{session['id']}/files"
        self.assertEqual(self.rpc(base + "/mkdir", "POST", {"path": path})["status"], 200)
        self.assertEqual(self.rpc(base + "/chmod", "POST", {"path": path, "permissions": 0o750})["status"], 200)
        listing = self.rpc(base, body={"path": str(self.home)})
        self.assertTrue(any(i["name"] == Path(path).name for i in listing["data"]["items"]))
        renamed = path + " renamed"
        self.assertEqual(self.rpc(base + "/rename", "POST", {"path": path, "target": renamed})["status"], 200)
        upload = self.rpc("transfers", "POST", {"direction": "upload", "session_id": session["id"], "path": renamed + "/payload 中文 '%.txt", "size": 5})["data"]
        self.assertEqual(self.rpc(f"transfers/{upload['id']}/commit", "POST")["status"], 409)
        self.assertEqual(self.rpc(f"transfers/{upload['id']}/chunk", "POST", {"offset": 0, "data": base64.b64encode(b"hello").decode()})["status"], 200)
        self.assertEqual(self.rpc(f"transfers/{upload['id']}/commit", "POST")["status"], 202)
        for _ in range(100):
            task = self.rpc("transfers/" + upload["id"])["data"]
            if task["state"] in ("completed", "failed"):
                break
            time.sleep(.05)
        self.assertEqual(task["state"], "completed", task)
        self.assertEqual(Path(renamed, "payload 中文 '%.txt").read_bytes(), b"hello")
        self.assertEqual(self.rpc("transfers/" + upload["id"], owner="another")["status"], 404)
        # A staged cancellation may never delete the existing remote target.
        staged = self.rpc("transfers", "POST", {"direction": "upload", "session_id": session["id"], "path": renamed + "/payload 中文 '%.txt", "size": 9, "replace": True})["data"]
        self.assertEqual(self.rpc(f"transfers/{staged['id']}/cancel", "POST")["status"], 200)
        self.assertEqual(Path(renamed, "payload 中文 '%.txt").read_bytes(), b"hello")
        download = self.rpc("transfers", "POST", {"direction": "download", "session_id": session["id"], "path": renamed + "/payload 中文 '%.txt"})["data"]
        for _ in range(100):
            downloaded = self.rpc("transfers/" + download["id"])["data"]
            if downloaded["state"] in ("completed", "failed"):
                break
            time.sleep(.03)
        self.assertEqual(downloaded["state"], "completed", downloaded)
        a, b = socket.socketpair()
        b.settimeout(8)
        try:
            result = self.rpc(f"transfers/{download['id']}/content", passed=a)
            self.assertTrue(result["data"]["fd_owned"])
            a.close()
            response = bytearray()
            while True:
                chunk = b.recv(32768)
                if not chunk:
                    break
                response.extend(chunk)
            header, content = bytes(response).split(b"\r\n\r\n", 1)
            self.assertEqual(content, b"hello")
            disposition = next(line for line in header.decode().split("\r\n") if line.startswith("Content-Disposition:"))
            self.assertEqual(unquote(disposition.split("filename*=UTF-8''", 1)[1]), "payload 中文 '%.txt")
        finally:
            a.close()
            b.close()
        self.assertEqual(self.rpc(f"transfers/{download['id']}/cancel", "POST")["status"], 200)
        self.assertEqual(self.rpc(base + "/delete", "POST", {"path": renamed, "confirmed": True, "recursive": True})["status"], 200)
        self.assertFalse(Path(renamed).exists())

    def test_05_telnet_negotiation_and_input(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        received = bytearray()
        stop = threading.Event()
        def server():
            conn, _ = listener.accept()
            conn.settimeout(.3)
            with conn:
                for part in [b"\xff", b"\xfd", b"\x1f", b"\xff\xfb\x01", b"login: "]:
                    conn.sendall(part)
                    time.sleep(.02)
                while not stop.is_set():
                    try:
                        data = conn.recv(4096)
                        if not data: break
                        received.extend(data)
                        if b"probe\r" in received:
                            conn.sendall("TELNET_OK 中文".encode())
                            received.extend(b"done")
                            break
                    except socket.timeout: pass
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        session, ws = self.start({"type": "telnet", "name": "telnet fixture", "address": "127.0.0.1", "port": listener.getsockname()[1]})
        ready = ws.until_state("ready")
        self.assertFalse(ready["capabilities"]["authenticated"])
        self.assertEqual(self.rpc(f"sessions/{session['id']}/system-info")["status"], 422)
        ws.send({"type": "resize", "cols": 91, "rows": 27})
        ws.send({"type": "input", "data": "probe\r"})
        output = b""
        for _ in range(30):
            op, data = ws.event()
            if op == 2:
                output += data
                if b"TELNET_OK" in output: break
        stop.set()
        thread.join(2)
        self.assertIn("TELNET_OK 中文".encode(), output)
        self.assertIn(b"\xff\xfb\x1f", received)
        self.assertIn(b"\xff\xfa\x1f", received)
        self.assertNotIn(b"\xff\xfd", output)

    def test_06_auth_fail_and_changed_host_key_never_ready(self):
        if not self.sshd:
            self.skipTest("isolated sshd not configured")
        host = {"type": "ssh", "name": "bad auth", "address": "127.0.0.1", "port": self.port, "username": self.user}
        session, ws = self.start(host, {"type": "password", "password": "invalid-fixture-password"})
        failed = ws.until_state("failed")
        self.assertEqual(failed["reason"], "ssh_auth_failed")
        self.assertEqual(failed["ready_at"], 0)
        with sqlite3.connect(self.home / "state.db") as db:
            db.execute("UPDATE host_keys SET fingerprint=? WHERE address=? AND port=?", ("SHA256:fixture-changed", "127.0.0.1", self.port))
        _, other = self.start(host)
        failed = other.until_state("failed")
        self.assertEqual(failed["reason"], "host_key_changed")
        self.assertEqual(failed["ready_at"], 0)
        self.assertEqual(failed["previous_fingerprint"], "SHA256:fixture-changed")

    def test_07_missing_serial_is_explicit_failure(self):
        session, ws = self.start({"type": "serial", "name": "missing serial", "device_id": "/dev/serial/by-id/dwrt-test-missing"})
        failed = ws.until_state("failed")
        self.assertEqual(failed["reason"], "serial_not_found")
        self.assertEqual(failed["ready_at"], 0)
        invalid = self.rpc("sessions", "POST", {"host": {"type": "serial", "name": "bad baud", "device_id": "/dev/serial/by-id/dwrt-test-missing", "baud_rate": 12345}, "workspace_id": "test"})
        self.assertEqual(invalid["status"], 422)
        self.assertEqual(invalid["data"]["field"], "baud_rate")

    def test_08_accepted_transfer_survives_interactive_disconnect(self):
        if not self.sshd:
            self.skipTest("isolated sshd not configured")
        with sqlite3.connect(self.home / "state.db") as db:
            db.execute("DELETE FROM host_keys")
        session, ws = self.start({"type":"ssh", "name":"background transfer", "address":"127.0.0.1", "port":self.port, "username":self.user}, {"type":"key", "private_key":(self.home / "client").read_text(), "passphrase":"fixture-passphrase"})
        pending = ws.until_state("host_key_confirmation_required")
        self.rpc(f"sessions/{session['id']}/trust", "POST", {"fingerprint":pending["fingerprint"]})
        ws.until_state("ready")
        contents = bytes(range(256)) * (8 * 1024 * 1024 // 256)
        path = self.home / "background-transfer.bin"
        task = self.rpc("transfers", "POST", {"direction":"upload", "session_id":session["id"], "path":str(path), "size":len(contents)})["data"]
        for offset in range(0,len(contents),32768):
            response = self.rpc(f"transfers/{task['id']}/chunk", "POST", {"offset":offset, "data":base64.b64encode(contents[offset:offset+32768]).decode()})
            self.assertEqual(response["status"],200,response)
        self.assertEqual(self.rpc(f"transfers/{task['id']}/commit", "POST")["status"],202)
        self.assertEqual(self.rpc(f"sessions/{session['id']}/disconnect", "POST")["status"],200)
        ws.peer.close()
        max_latency = 0
        for _ in range(300):
            started=time.monotonic();self.assertEqual(self.rpc("capabilities")["status"],200)
            max_latency=max(max_latency,time.monotonic()-started)
            final=self.rpc("transfers/"+task["id"])["data"]
            if final["state"] in ("completed","failed","cancelled"):break
            time.sleep(.05)
        self.assertEqual(final["state"],"completed",final)
        self.assertEqual(path.read_bytes(),contents)
        self.assertLess(max_latency,1.0)
        self.assertEqual(self.rpc("transfers/"+task["id"],owner="another")["status"],404)

    def test_09_missing_sftp_keeps_ssh_ready(self):
        if not self.sshd:
            self.skipTest("isolated sshd not configured")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
        config=(self.home/"sshd.conf").read_text().replace(f"Port {self.port}",f"Port {port}").replace("Subsystem sftp internal-sftp\n","").replace("sshd.pid","no-sftp.pid")
        path=self.home/"no-sftp.conf";path.write_text(config)
        log=(self.home/"no-sftp.log").open("wb")
        proc=subprocess.Popen([os.environ["TM_TEST_SSHD"],"-D","-e","-f",str(path)],stdout=log,stderr=log)
        def cleanup():
            proc.terminate();proc.wait(timeout=5);log.close()
        self.addCleanup(cleanup);time.sleep(.3)
        session,ws=self.start({"type":"ssh","name":"without sftp","address":"127.0.0.1","port":port,"username":self.user},{"type":"key","private_key":(self.home/"client").read_text(),"passphrase":"fixture-passphrase"})
        pending=ws.until_state("host_key_confirmation_required")
        self.rpc(f"sessions/{session['id']}/trust","POST",{"fingerprint":pending["fingerprint"]})
        ready=ws.until_state("ready");self.assertFalse(ready["capabilities"]["sftp"])
        self.assertEqual(self.rpc(f"sessions/{session['id']}/files",body={"path":str(self.home)})["status"],422)
        self.assertEqual(self.rpc(f"sessions/{session['id']}/system-info")["status"],200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
