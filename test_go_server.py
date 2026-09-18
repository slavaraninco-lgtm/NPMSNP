import socket
import hashlib
import json
import urllib.request
import time
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def test_integration():
    print("=== Testing NPMSNP Go Server Integration ===")
    
    # 1. Test HTTP Server
    print("[1] Testing HTTP Endpoints on port 1865...")
    req = urllib.request.Request("http://127.0.0.1:1865/rdr/pprdr.asp")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        passport_urls = resp.headers.get("PassportURLs")
        print(f"  -> /rdr/pprdr.asp OK: PassportURLs = {passport_urls}")
        assert passport_urls and "DALogin=" in passport_urls

    req2 = urllib.request.Request("http://127.0.0.1:1865/login-mock")
    with urllib.request.urlopen(req2) as resp:
        assert resp.status == 200
        auth_info = resp.headers.get("Authentication-Info")
        print(f"  -> /login-mock OK: Authentication-Info = {auth_info}")
        assert auth_info and "da-status=success" in auth_info

    # 2. Test Admin API Stats
    print("[2] Testing Web Admin API /api/stats...")
    with urllib.request.urlopen("http://127.0.0.1:1865/api/stats") as resp:
        assert resp.status == 200
        stats = json.loads(resp.read().decode("utf-8"))
        print(f"  -> Stats: {stats}")
        assert stats.get("project_name") == "NPMSNP"
        assert stats.get("status") == "running"

    # 3. Test NS Connection (MD5 Handshake)
    print("[3] Testing Notification Server (NS) on port 1863...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 1863))
    
    def send_line(line):
        s.sendall(line.encode("utf-8") + b"\r\n")

    def recv_line():
        buf = b""
        while not buf.endswith(b"\r\n"):
            chunk = s.recv(1)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", errors="replace").rstrip("\r\n")

    # VER
    send_line("VER 1 MSNP9 MSNP8 CVR0")
    line = recv_line()
    print(f"  NS <- {line}")
    assert line.startswith("VER 1 MSNP9")

    # CVR
    send_line("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS test@msn.local")
    line = recv_line()
    print(f"  NS <- {line}")
    assert line.startswith("CVR 2")

    # USR MD5 I
    send_line("USR 3 MD5 I test@msn.local")
    line = recv_line()
    print(f"  NS <- {line}")
    assert line.startswith("USR 3 MD5 S ")
    challenge = line.split()[4]

    # Compute response with password 'pass123'
    resp_hash = hashlib.md5((challenge + "pass123").encode("utf-8")).hexdigest()
    send_line(f"USR 4 MD5 S {resp_hash}")
    line = recv_line()
    print(f"  NS <- {line}")
    assert line.startswith("USR 4 OK test@msn.local")

    # SYN
    send_line("SYN 5 0")
    syn_line = recv_line()
    print(f"  NS <- {syn_line}")
    assert syn_line.startswith("SYN 5 ")
    parts = syn_line.split()
    num_contacts = int(parts[3]) if len(parts) > 3 else 0
    num_groups = int(parts[4]) if len(parts) > 4 else 0

    # Read GTC and BLP
    l_gtc = recv_line()
    print(f"  NS <- {l_gtc}")
    l_blp = recv_line()
    print(f"  NS <- {l_blp}")

    # Read all PRG lines
    for _ in range(num_groups):
        l_prg = recv_line()
        print(f"  NS (PRG) <- {l_prg}")

    # Read all LST lines
    for _ in range(num_contacts):
        l_lst = recv_line()
        print(f"  NS (LST) <- {l_lst}")

    # CHG
    send_line("CHG 6 NLN 0")
    line = recv_line()
    print(f"  NS <- {line}")
    assert line.startswith("CHG 6 NLN")

    # Read any initial presence ILN lines that arrived
    # PNG -> QNG
    send_line("PNG")
    while True:
        line = recv_line()
        print(f"  NS <- {line}")
        if line.startswith("QNG"):
            break
        elif line.startswith("ILN"):
            continue
    assert line.startswith("QNG 60")

    # XFR SB
    send_line("XFR 7 SB")
    line = recv_line()
    print(f"  NS <- {line}")
    assert "SB" in line and "CKI" in line
    parts = line.split()
    sb_addr = parts[3]
    sb_cookie = parts[5]

    send_line("OUT")
    s.close()
    print("  -> NS session completed successfully!")

    # 4. Test SB Connection (Switchboard)
    print(f"[4] Testing Switchboard Server (SB) on port 1864 with cookie {sb_cookie}...")
    sb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sb_sock.connect(("127.0.0.1", 1864))

    def sb_send(line):
        sb_sock.sendall(line.encode("utf-8") + b"\r\n")

    def sb_recv():
        buf = b""
        while not buf.endswith(b"\r\n"):
            chunk = sb_sock.recv(1)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", errors="replace").rstrip("\r\n")

    # SB USR
    sb_send(f"USR 1 test@msn.local {sb_cookie}")
    sb_resp = sb_recv()
    print(f"  SB <- {sb_resp}")
    assert sb_resp.startswith("USR 1 OK test@msn.local")

    # CAL to system service bot
    sb_send("CAL 2 system@msn.local")
    cal_resp = sb_recv()
    print(f"  SB <- {cal_resp}")
    assert "RINGING" in cal_resp
    joi_resp = sb_recv()
    print(f"  SB <- {joi_resp}")
    assert "JOI system@msn.local" in joi_resp

    # Send MSG in room
    msg_body = "Hello Go MSNP Server!"
    payload = f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{msg_body}"
    sb_sock.sendall(f"MSG 3 U {len(payload.encode('utf-8'))}\r\n".encode("utf-8") + payload.encode("utf-8"))
    
    # Receive response from service bot
    header = sb_recv()
    print(f"  SB <- {header}")
    assert "MSG system@msn.local" in header

    sb_send("OUT")
    sb_sock.close()
    print("  -> Switchboard session completed successfully!")

    # 5. Test Admin API Flow
    print("[5] Testing Admin API Flow on port 1865...")
    login_data = json.dumps({"password": "admin123"}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:1865/api/admin/login", data=login_data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            login_res = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError:
        # Try password 123456
        login_data = json.dumps({"password": "123456"}).encode("utf-8")
        req = urllib.request.Request("http://127.0.0.1:1865/api/admin/login", data=login_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            login_res = json.loads(resp.read().decode("utf-8"))

    admin_token = login_res.get("token")
    print(f"  -> Admin login successful, token: {admin_token[:10]}...")

    # Check auth
    req = urllib.request.Request("http://127.0.0.1:1865/api/admin/check", headers={"X-Admin-Token": admin_token})
    with urllib.request.urlopen(req) as resp:
        chk = json.loads(resp.read().decode("utf-8"))
        assert chk.get("authenticated") is True
        print("  -> Admin check: authenticated = True")

    # Get users
    req = urllib.request.Request("http://127.0.0.1:1865/api/users", headers={"X-Admin-Token": admin_token})
    with urllib.request.urlopen(req) as resp:
        users_res = json.loads(resp.read().decode("utf-8"))
        users = users_res.get("users", [])
        print(f"  -> Total users listed by Admin API: {len(users)}")
        assert len(users) >= 7

    # Public registration
    reg_data = json.dumps({"email": "gonewbie@msn.local", "password": "gopassword", "friendly_name": "Go Newbie"}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:1865/api/register", data=reg_data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            reg_res = json.loads(resp.read().decode("utf-8"))
            print(f"  -> Registration response: {reg_res}")
            assert reg_res.get("success") is True
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print("  -> User already registered (Conflict), OK")
        else:
            raise

    print("\n=== ALL INTEGRATION TESTS PASSED WITH 100% SUCCESS! ===")

if __name__ == "__main__":
    test_integration()

