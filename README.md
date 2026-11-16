# Enterprise Layer-7 Application Proxy Firewall & Web Traffic Filter (v2.1)

A production-ready, modular, zero-dependency Layer-7 Application Proxy Firewall and Web Traffic Filter built purely in Python 3.10+ using only standard library modules. Designed for cross-platform execution on both Windows 11 and Linux environments.

---

## Key Features

- **Zero-Dependency Architecture:** Powered strictly by Python's built-in standard library (`socket`, `threading`, `select`, `struct`, `sqlite3`, `hashlib`, `hmac`, `secrets`, `ipaddress`, `urllib.parse`, `collections`, `configparser`, `logging`). No external packages or compilers required.
- **Stateful Packet Inspection (SPI):** 5-tuple connection flow tracker `(src_ip, dst_ip, src_port, dst_port, protocol)` maintaining connection state lifecycles (`NEW`, `ESTABLISHED`, `CLOSING`) with protocol-specific expiration timers and background garbage collection.
- **Deep Packet Inspection (DPI) & WAF Scanner:** Pre-compiled regular expression engine detecting SQL Injection (SQLi), Cross-Site Scripting (XSS), cleartext credential exposure, and command injection across URLs, headers, query parameters, and bodies.
- **Encrypted HTTPS TLS SNI Inspection:** Zero-certificate TLS ClientHello struct parser analyzing encrypted TCP 443 handshakes to inspect Server Name Indication (SNI) hostnames without SSL termination or certificate authority installation.
- **Intrusion Detection & Prevention System (IDS/IPS):** Token-bucket rate limiting per IP, abnormal TCP flag inspection (NULL scans, XMAS scans, stealth SYN scans), and automated time-based mitigation banning with SQLite persistence.
- **Management Failsafe & Input Hardening:** Hardcoded safety layer prevents accidental administrative lockout (Web Dashboard port 8081, SSH port 22) even when wildcard drop rules (`0.0.0.0/0`) are committed. All CIDR and port inputs undergo strict standard library validation.
- **Real-Time SOC Web Telemetry Dashboard:** Responsive dark-mode dashboard streaming live telemetry via Server-Sent Events (SSE) and a 60-second sliding time-series ring buffer (`collections.deque`), complete with offline CIDR geo-prefix location tagging.
- **Authentication & Role-Based Access Control (RBAC):** Salted PBKDF2-HMAC-SHA256 password hashing with cryptographically secure session tokens (`secrets.token_hex(32)`) enforcing permissions (`ADMIN` rule mutations vs `AUDITOR` read-only viewing).
- **Offline Cryptographic Licensing:** HMAC-SHA256 signed activation key validator enforcing operational tiers (`ENTERPRISE`, `STANDARD`, `TRIAL`), expiration dates, and machine hardware identifiers (`hwid`).
- **Headless CLI Administration:** Comprehensive command-line utility (`cli_admin.py`) for automated deployments, status checks, rule management, manual banning/unbanning, and JSON/CSV log exports.

---

## System Architecture

```text
       Incoming Client Request (HTTP / HTTPS CONNECT)
                           │
                           ▼
              ┌─────────────────────────┐
              │     Raw Socket Listener │ ──> Port 8080 (TCP / L7 Proxy)
              └────────────┬────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
  ┌──────────────────────┐    ┌──────────────────────┐
  │  IDS Rate Limiter    │    │  SPI State Tracker   │
  │  & TCP Flag Analysis │    │  (5-tuple tracking)  │
  └──────────┬───────────┘    └──────────┬───────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
              ┌─────────────────────────┐
              │    Priority ACL Engine  │ ──> Port Failsafe (8081, 22)
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   DPI & TLS SNI Parser  │ ──> Domain & Path Blacklists
              │   (SQLi, XSS, CmdInj)   │     TLS ClientHello Struct Unpack
              └────────────┬────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
   [ Threat Detected ]           [ Clean Request ]
            │                             │
    HTTP 403 Block Page         Upstream Forward / Tunnel
    + SQLite Security Event     + Bidirectional Relay
    + CSV Audit Log             + Telemetry Ring Buffer
```

---

## Plug-and-Play Quickstart

### Prerequisites
- Python 3.10 or higher (Python 3.11+ recommended).
- Supported platforms: Windows 11, Windows 10, Kali Linux, Ubuntu, Debian, CentOS/RHEL.
- No third-party packages needed (uses standard library exclusively).

### 1. Clone the Repository
```bash
git clone https://github.com/MuhammadInshal231/enterprise-firewall.git
cd enterprise-firewall
```

### 2. Automated Setup (Single Command)

**Linux / macOS:**
```bash
python3 setup.py
# or: ./install.sh
```

**Windows 11:**
```cmd
python setup.py
:: or double-click install.bat
```

### 3. Launch the Firewall & Dashboard
```bash
python main.py
```

### 4. Access the Web SOC Dashboard
```text
http://127.0.0.1:8081
```

Default credentials:
- **Administrator (`ADMIN`):** Username: `admin` | Password: `admin123`
- **Auditor (`AUDITOR`):** Username: `auditor` | Password: `auditor123`

**⚠️ Change these immediately — do not run this in any real or exposed environment with the default credentials still active.**

---

## Headless CLI Administration

```bash
python cli_admin.py status
python cli_admin.py rules list
python cli_admin.py rules add --priority 120 --action DROP --cidr 10.0.0.0/8 --port 80
python cli_admin.py rules delete --id 3
python cli_admin.py ban 198.51.100.55 300 "Suspicious Port Scan"
python cli_admin.py unban 198.51.100.55
python cli_admin.py license status
python cli_admin.py export rules
python cli_admin.py export logs
```

---

## Verification & Automated Testing

```bash
python verification/verify_system_e2e.py
python verification/verify_acl_evaluator.py
python verification/verify_dpi_signatures.py
python verification/verify_ids_mitigation.py
python verification/verify_spi_engine.py
```

---

## License

This project is licensed under **Creative Commons Attribution 4.0 (CC BY 4.0)** — see [LICENSE](LICENSE) for the full terms.

Additional usage guidelines, including a prohibition on unlawful use, are in [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

---

## Author

**Muhammad Inshal**  
[LinkedIn](https://www.linkedin.com/in/muhammad-inshal-25ba292aa)
