# WINAP V1 — Design Notes

## Execution flow

1. Validate the target environment (Windows Server 2022 and Windows PowerShell 5.1).
2. Parse and validate the JSON configuration. Invalid configuration stops the run before any configuration-changing action.
3. Collect read-only inventory.
4. Audit SMBv1 server protocol, Windows Firewall profiles, and configured TLS indicators.
5. Evaluate allowlisted feature requests. Feature installation requires both configuration opt-in and `-InstallFeatures`.
6. Evaluate SMBv1 server remediation. Remediation requires configuration opt-in, `-RemediateSMB1`, `-AcknowledgeSMB1Impact`, administrator privileges, supported cmdlets, a clear state, and a post-change check.
7. Write execution log and standalone HTML report.

## Safety invariants

- Audit-only is the default.
- Configuration is validated before any requested mutation.
- The only remediation target is the SMBv1 server protocol.
- Firewall and TLS checks are read-only.
- The hostname is inventory-only.
- No automatic reboot occurs.
- Unknown or ambiguous states are not silently converted into success.
- Optional features must be in the fixed allowlist and explicitly requested.

## Result meanings

- `PASS`: the observed state matched the expected state, or an action was verified.
- `FAIL`: a known state does not match the expected state, or an operation failed.
- `WARN`: an operation reported an error but a follow-up check found the intended state.
- `UNKNOWN`: the state or result could not be reliably established.
- `SKIPPED`: the action was not attempted due to missing opt-in or a failed safety condition.
- `INFO`: informational outcome, preview, or audit-only item.

## Test boundary

The built-in test harness tests configuration safety and report generation without invoking the remediation function. End-to-end testing and any change operation must be performed deliberately in an isolated, non-production Windows Server 2022 VM.
