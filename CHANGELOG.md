
# Changelog

All notable changes to WINAP are documented here. Entries describe actual changes and verified results.

## Unreleased

### Phase 2 — Configuration and Safety Validation

- Fixed inventory collection so `LastBootUpTime` handles `DateTime` values and safely falls back to `Unknown` when the value is missing or conversion fails.
- Updated the unknown-configuration-key test to use `Add-Member`, compatible with Windows PowerShell 5.1.
- Built-in tests: 11 passed, 0 failed.
- Windows Server preview: 11 results, 6 PASS, 0 FAIL, 0 UNKNOWN.
- Preview confirmed that inventory was collected and remediation remained skipped under the audit-only default.

### Verification limitations

- The current test suite does not yet cover every TDD acceptance criterion.
- TLS messages are informational; the current Preview output does not establish that each TLS protocol is enabled or disabled.
- SMBv1 remediation has not been tested and remains outside this audit-only verification run.

## [0.1.0] - 2026-10-24

### Phase 1 — Baseline

- Established the initial WINAP repository file structure and implementation baseline.
- Included the example JSON configuration, PowerShell entry point/module, and built-in test harness.
- Initial implementation had not yet been verified on the target Windows Server 2022 environment.
