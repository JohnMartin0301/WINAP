# Changelog

All notable changes to WINAP are documented here. Entries describe actual changes and verified results; pending runtime checks are identified explicitly.

## Unreleased

### Phase 3 — Baseline Auditing (runtime verification pending)

- Updated SMBv1 auditing to report missing or non-Boolean state as `UNKNOWN` rather than coercing it to `False`.
- Updated firewall auditing to report Domain, Private, and Public profiles separately, including unavailable or ambiguous states.
- Updated TLS auditing to inspect configured server-side Schannel indicators even when a protocol is configured as `AuditOnly`; absent or ambiguous values remain `UNKNOWN`.
- Expanded the built-in test harness to check for the seven expected audit results and conservative `AuditOnly` TLS statuses.
- Runtime verification of these Phase 3 changes is pending on the Windows Server 2022 VM.

### Phase 2 — Configuration and Safety Validation

- Fixed inventory collection so `LastBootUpTime` handles `DateTime` values and safely falls back to `Unknown` when the value is missing or conversion fails.
- Updated the unknown-configuration-key test to use `Add-Member`, compatible with Windows PowerShell 5.1.
- Previously reported built-in tests: 11 passed, 0 failed.
- Previously reported Windows Server Preview: 11 results, 6 PASS, 0 FAIL, 0 UNKNOWN.
- These earlier results do not verify the Phase 3 changes in this package.

### Verification limitations

- The built-in tests do not replace the target VM integration run.
- TLS defaults and policy may depend on Windows configuration; absent or ambiguous registry indicators are not interpreted as proof of enabled or disabled state.
- SMBv1 remediation and feature installation are not part of Phase 3 execution and must not be triggered during the audit verification run.

## [0.1.0] - 2026-10-24

### Phase 1 — Baseline

- Established the initial WINAP repository file structure and implementation baseline.
- Included the example JSON configuration, PowerShell entry point/module, and built-in test harness.
- Initial implementation had not yet been verified on the target Windows Server 2022 environment.