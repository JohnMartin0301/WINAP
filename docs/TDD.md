# WINAP Technical Design Document (TDD)

**Version:** 0.1
**Project:** WINAP V1
**Platform:** Windows Server 2022
**Primary technology:** Windows PowerShell 5.1
**Execution model:** Local, single-server execution
**Deployment model:** Personal virtual-machine environment
**Cost target:** Entirely free

## Source-of-truth note

The complete TDD supplied by the project owner is the authoritative design draft. Insert that complete, unchanged text into this file before the Phase 1 baseline commit. The complete draft is not reproduced here because it must be preserved verbatim rather than silently summarized or altered.

## Design summary

WINAP is a local PowerShell tool for Windows Server 2022. Its intended scope includes JSON configuration validation, read-only inventory including hostname, auditing of SMBv1 server protocol state, Windows Firewall profiles and selected TLS indicators, minimal allowlisted feature management, guarded SMBv1 server-only remediation, post-change verification, execution logs, and a standalone HTML report.

Audit-only behavior is the default. Hostname, network, firewall and TLS changes are excluded. SMBv1 client settings are out of scope. There must be no automatic reboot, database, backend, cloud service, dashboard, or multi-server orchestration. Pester is to be used only after compatibility is verified; otherwise, a built-in test harness is required.
