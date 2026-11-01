# CVE-2026-109618 / CVE-2026-109619: PHP Use-After-Free via `zend_bailout()` in Serialization

A 100% reliable denial-of-service PoC exploiting a use-after-free in PHP's serialization subsystem (`BG(serialize)`).

## The Bug

When `serialize()` hits `memory_limit`, PHP calls `zend_bailout()` — a `longjmp()` that skips all cleanup, including `php_var_serialize_destroy()`. This leaves `BG(serialize).level = 1` and `BG(serialize).data` pointing to freed ZMM heap memory.

On the **next request** to the same Apache prefork worker, the upload-progress callback fires during `php_hash_environment()` — **before** `ext/standard`'s RINIT resets `BG(serialize)`. The callback calls `php_var_serialize_init()`, which sees `level > 0` and reuses the dangling `data` pointer. The freed address now holds ZMM chunk bookkeeping → `SIGSEGV`.

## Affected Versions

- PHP 8.0 – 8.3.x (tested on 8.3.20)
- Apache with `mod_php` and `prefork` MPM
- `session.upload_progress.enabled = On` (PHP default)

## Files

| File | Description |
|------|-------------|
| `poc.py` | Full exploit script — sends two HTTP requests on one keep-alive connection |
| `trigger_serialize_bailout.php` | Request A: triggers OOM during `serialize()` to dirty `BG(serialize)` |
| `target.php` | Request B: any PHP endpoint — the crash happens during multipart parsing |
| `docker-compose.yml` | Lab environment: WordPress 6.7 + PHP 8.3 + Apache prefork |
| `php-config/php.ini` | PHP config with `memory_limit = 16M` and upload-progress enabled |
| `exploit.pcap` | Packet capture of a successful crash |

## Quick Start

```bash
# 1. Start the lab
docker compose up -d

# 2. Wait for WordPress to initialize (~30s)
curl -s http://localhost:8080/ > /dev/null

# 3. Run the PoC
python3 poc.py http://localhost:8080
```

The PoC sends two requests on a single TCP connection:
1. **GET** `trigger_serialize_bailout.php` — OOM mid-serialize poisons `BG(serialize)`
2. **POST** `target.php` — multipart upload with `PHP_SESSION_UPLOAD_PROGRESS` triggers UAF → crash

Expected output:
```
[*] Target: http://localhost:8080
[*] Worker PID (from OOM response): 234
[*] Request B: triggering UAF on same worker...
[+] Worker crashed! (connection reset / empty response)
```

## Impact

- **DoS**: 100% reliable, single unauthenticated request pair kills an Apache worker
- **RCE potential**: The UAF gives control over a `HashTable` with a `pDestructor` function pointer. In Apache prefork, ASLR layout is stable across requests (fork inherits parent's address space), and the attacker controls heap content via multipart data on the new ZMM heap.

## Timeline

- **2026-10-14**: Reported to PHP security team
- **2026-10-18**: CVE-2026-109618 and CVE-2026-109619 assigned
- **2026-10-21**: Public disclosure

## Blog Post

Full technical writeup: [CVE-2026-109618 CVE-2026-109619 PHP Use-After-Free: From zend_bailout() to 100% Reliable PoC](https://blog.al4n4n.com/CVE-2026-109618-CVE-2026-109619-PHP-UAF-zend-bailout/)
