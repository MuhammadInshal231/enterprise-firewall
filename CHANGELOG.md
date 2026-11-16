# Changelog

All notable changes to this project are documented in this file.

## [2.1.0] - 2025-02-14

### Added
- Created `LICENSE` containing proprietary "All Rights Reserved" enterprise licensing terms.
- Created `core/license_manager.py` implementing offline HMAC-SHA256 signature validation for `TRIAL`, `STANDARD`, and `ENTERPRISE` license keys.
- Created `dashboard/auth.py` providing session token management, PBKDF2-HMAC-SHA256 password hashing, and Role-Based Access Control (RBAC).
- Created `core/tls_sni.py` offering zero-certificate TLS ClientHello packet parsing to extract Server Name Indication (SNI) hostnames over TCP 443.
- Created `cli_admin.py` providing a headless command-line interface for status checks, ACL rule management, IP banning, and diagnostic exports.
- Implemented real-time bidirectional synchronization between `config/rules.json` and `firewall.db`.
- Added data export HTTP endpoints `/api/export/rules` (JSON) and `/api/export/logs` (CSV).
- Added a 60-second sliding time-series telemetry ring buffer (`collections.deque`) in `core/telemetry.py` streaming over `/api/stream` Server-Sent Events.
- Implemented offline CIDR geo-prefix tagging for logged security events and active connection inspection.

### Changed (In-Place Refactoring)
- Refactored project folder structure in place to enforce standard enterprise naming conventions.
- Renamed testing directory `tests/` to `verification/`.
- Renamed all validation scripts:
  - `tests/test_firewall.py` -> `verification/verify_system_e2e.py`
  - `tests/test_state.py` -> `verification/verify_spi_engine.py`
  - `tests/test_ids.py` -> `verification/verify_ids_mitigation.py`
  - `tests/test_dpi.py` -> `verification/verify_dpi_signatures.py`
  - `tests/test_rules.py` -> `verification/verify_acl_evaluator.py`
- Upgraded `dashboard/server.py` to intercept unauthenticated API mutations and enforce access controls.
- Integrated `logging.handlers.RotatingFileHandler` across network engines to prevent unbounded log growth.

### Security Hardening
- Implemented automatic administrative management port bypass safeguards to prevent lockout via custom wildcard ACL rules.
- Enforced strict CIDR block and port validation using standard `ipaddress` models prior to committing rules to state memory.
- Hardened HTTP API endpoints against session fixation, header injection, and malformed JSON payloads.

### Verification Suite Updates
- Updated all end-to-end and unit verification modules in `verification/` to target updated core class interfaces.
- Added test coverage for offline cryptographic license validation, SNI parsing logic, and dynamic authentication tokens.
- Confirmed zero-dependency compliance across all `.py` files using only standard library utilities.
- Audited all files to ensure strict compliance with the zero-comment policy across the entire codebase.

