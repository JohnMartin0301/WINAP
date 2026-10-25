# Changelog

All notable changes to WINAP are documented here. Entries describe actual changes and verified results; pending runtime checks are identified explicitly.

## [0.5.0] - 2026-10-25

### Phase 5 — Reporting and End-to-End Testing

- Improved HTML reporting and execution logging with run metadata, inventory details, accurate status counts, and overall run status.
- Added reporting error handling, HTML output escaping, and validation to prevent report/log filename collisions.
- Expanded the built-in test harness to cover reporting, status accuracy, and output failure scenarios.
- Verified 51 tests passed, 0 failed; Preview returned 11 results, with 6 PASS, 0 FAIL, 3 UNKNOWN, and 1 SKIPPED. The HTML report and execution log were generated successfully.

## [0.4.0] - 2026-10-25

### Phase 4 — Controlled Operations

- Added guarded SMBv1 remediation and safety checks.
- Added tests for remediation safeguards, failure handling, and verification.
- Corrected the application entry point and Windows PowerShell 5.1 logging compatibility.
- Verified 40 tests passed; Preview generated the HTML report and execution log. No actual remediation was performed.

## [0.3.0] - 2026-10-24

### Phase 3 — Baseline Auditing

- Updated SMBv1 auditing to report missing or non-Boolean state as `UNKNOWN` rather than coercing it to `False`.
- Updated firewall auditing to report Domain, Private, and Public profiles separately, including unavailable or ambiguous states.
- Updated TLS auditing to inspect configured server-side Schannel indicators even when a protocol is configured as `AuditOnly`; absent or ambiguous values remain `UNKNOWN`.
- Expanded the built-in test harness to check for the seven expected audit results and conservative `AuditOnly` TLS statuses.

## [0.2.0] - 2026-10-24

### Phase 2 — Configuration and Safety Validation

- Fixed inventory collection so `LastBootUpTime` handles `DateTime` values and safely falls back to `Unknown` when the value is missing or conversion fails.
- Updated the unknown-configuration-key test to use `Add-Member`, compatible with Windows PowerShell 5.1.
- Previously reported built-in tests: 11 passed, 0 failed.
- Previously reported Windows Server Preview: 11 results, 6 PASS, 0 FAIL, 0 UNKNOWN.

## [0.1.0] - 2026-10-24

### Phase 1 — Baseline

- Established the initial WINAP repository file structure and implementation baseline.
- Included the example JSON configuration, PowerShell entry point/module, and built-in test harness.
- Initial implementation had not yet been verified on the target Windows Server 2022 environment.