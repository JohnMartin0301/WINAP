# WINAP --- Windows Infrastructure Automation Platform

## Technical Design Document (TDD)

  Document field              Value
  --------------------------- --------------------------------------
  **Version**                 0.1
  **Project**                 WINAP V1
  **Platform**                Windows Server 2022
  **Primary technology**      Windows PowerShell 5.1
  **Execution model**         Local, single-server execution
  **Deployment model**        Personal virtual-machine environment
  **Cost target**             Entirely free
  **Implementation status**   Not started --- pending TDD approval

------------------------------------------------------------------------

## 1. Project Overview

WINAP (Windows Infrastructure Automation Platform) is a PowerShell-based
tool designed to simplify repetitive Windows Server configuration and
validation tasks. It addresses the time and effort required to manually
check server settings, verify security baselines, identify configuration
issues, and document results. WINAP aims to make these tasks more
consistent, repeatable, and easier to review.

### 1.1 What WINAP Does

WINAP V1 provides a focused set of capabilities for a single Windows
Server environment:

-   **Configuration validation:** Reads and validates a JSON
    configuration file before execution.
-   **Server inventory:** Collects basic server information, including
    the current hostname, without changing it.
-   **Baseline auditing:** Checks SMBv1 server protocol status, Windows
    Firewall profiles, and selected TLS configuration indicators.
-   **Feature management:** Optionally manages approved Windows Server
    roles or features using a minimal, explicitly defined allowlist.
-   **Controlled remediation:** Supports only SMBv1 server protocol
    remediation, subject to explicit authorization and safety checks.
-   **Verification and reporting:** Rechecks the system after an
    attempted change, records execution details, and generates a
    standalone HTML report.

### 1.2 How WINAP Works

WINAP begins by checking the execution environment and validating its
JSON configuration. It then collects server inventory and previews
planned operations where requested. The tool audits the selected
baseline settings and, if explicitly enabled, manages only approved
features. Remediation is optional and restricted to the SMBv1 server
protocol; uncertain or unsafe conditions must prevent the change. After
an attempted remediation, WINAP verifies the resulting state where
possible, records successes and failures in its logs, and generates an
HTML report summarizing findings, actions, warnings, and errors.

### 1.3 Why WINAP Is Useful

WINAP demonstrates how PowerShell can turn repetitive Windows Server
checks into a structured, repeatable workflow. It combines
configuration-driven execution, baseline validation, controlled changes,
error handling, and evidence generation in one small project. This
provides practical experience relevant to Windows Server engineering and
infrastructure automation while making the results easier to understand
and demonstrate.

### 1.4 V1 Scope at a Glance

-   **Target environment:** Windows Server 2022, using Windows
    PowerShell 5.1, subject to environment verification.
-   **Inputs:** JSON configuration and the server's current state.
-   **Outputs:** Execution logs, audit and verification results, and a
    standalone HTML report.
-   **Core capabilities:** Inventory, baseline auditing, minimal
    allowlisted feature management, and guarded SMBv1 server protocol
    remediation.
-   **Major exclusions:** Hostname changes, network reconfiguration,
    multi-server management, broad vulnerability scanning, additional
    remediation targets, databases, backends, cloud services, and web
    dashboards.

WINAP V1 is intended for an isolated, non-production environment and is
designed to remain lightweight, free to build, and manageable on a
resource-constrained laptop.

## 2. Purpose

WINAP is a lightweight Windows infrastructure automation tool that
applies a small, explicitly defined configuration baseline, checks
selected Windows Server security and configuration settings, optionally
performs a narrowly scoped remediation, and produces a report of its
findings.

The project demonstrates practical Windows Server engineering,
PowerShell automation, configuration-driven execution, safe change
handling, validation, logging, and reporting.

WINAP V1 will prioritize reliability, clarity, and demonstrable
technical value over feature count or architectural complexity.

## 3. Business Problem

Windows Server build and validation activities often involve repetitive
manual checks, configuration verification, security baseline reviews,
and evidence collection.

Manual processes can lead to inconsistent results, missed checks,
repeated effort, and time-consuming reporting.

WINAP addresses this problem by providing a repeatable,
configuration-driven workflow for a small set of server checks and
approved configuration tasks.

The project is an educational and portfolio-oriented implementation. It
is not intended to replace enterprise configuration-management
platforms, vulnerability scanners, or production change-management
procedures.

## 4. Problem Statement

The project must demonstrate how a PowerShell-based tool can:

-   Read and validate a structured JSON configuration.
-   Inventory a Windows Server environment without renaming the server.
-   Evaluate a small, predefined set of configuration and security
    checks.
-   Restrict optional feature installation to a minimal allowlist.
-   Support explicit, narrowly scoped remediation.
-   Validate configuration state before and after permitted changes.
-   Record execution details and errors.
-   Generate a standalone HTML report.

The design must remain achievable on a Windows 11 laptop with 8 GB RAM,
using one Windows Server 2022 virtual machine.

## 5. Proposed Solution

WINAP will be a local PowerShell tool composed of a small entry-point
script, a reusable PowerShell module, a JSON configuration file,
validation and audit functions, a restricted remediation function, and
report-generation components.

The application will operate in audit-first mode. Remediation will
require an explicit operator choice.

The first release will support only one remediation target: the SMBv1
server protocol, and only when preflight checks establish that the
requested action is supported and safe to attempt. WINAP will not modify
the SMBv1 client configuration.

The project will not change the machine hostname. It will collect and
report the current hostname as inventory information.

### 5.1 Workflow

1.  **Preflight:** Verify the operating system, PowerShell environment,
    required commands, permissions, and configuration file.
2.  **Inventory:** Collect server identity and selected system details,
    including the existing hostname.
3.  **Validate configuration:** Parse the JSON configuration and reject
    invalid values or unsupported options.
4.  **Preview:** Display the intended checks and any proposed actions
    where requested, without applying changes.
5.  **Audit:** Evaluate the selected baseline checks and record the
    current state.
6.  **Configure approved features:** If explicitly enabled, install only
    features present in the approved minimal allowlist.
7.  **Remediate:** If explicitly requested, evaluate the SMBv1
    remediation safety conditions before considering a change.
8.  **Validate again:** Check the resulting state and distinguish
    successful changes from failed or unverified outcomes.
9.  **Report and log:** Generate a standalone HTML report and retain an
    execution log.

Audit and reporting should still provide useful results if an individual
check fails. Failures must be visible rather than silently ignored.

### 5.2 Architecture Diagram

``` mermaid
flowchart TD
    A[Operator] --> B[Invoke-WINAP.ps1]
    B --> C[Preflight and Configuration Validation]
    C --> D[Inventory Collection]
    D --> E[Execution Controller]

    E --> F[Preview and Audit]
    F --> G[Baseline Checks]

    E --> H[Approved Feature Management]
    H --> I[Minimal Feature Allowlist]

    E --> J[Optional Remediation]
    J --> K[SMBv1 Server Safety Gate]

    G --> L[Post-Execution Validation]
    I --> L
    K --> L

    L --> M[Execution Log]
    L --> N[Standalone HTML Report]
```

## 6. Intended Users

The primary user is the project developer operating a Windows Server
2022 virtual machine.

Secondary audiences include technical recruiters and infrastructure
engineers reviewing the source code, project documentation, test
evidence, and demonstration.

The interface will be a PowerShell command-line workflow. A web
application, GUI, API, or centralized management portal is not required.

## 7. Goals and Non-Goals

### 7.1 Goals

-   Demonstrate Windows Server configuration and validation using
    PowerShell.
-   Use a clear, maintainable PowerShell module structure.
-   Use JSON to control supported behavior.
-   Make audit mode the default.
-   Require explicit opt-in for remediation.
-   Restrict feature management to a small allowlist.
-   Avoid unrequested system changes.
-   Validate results and produce useful failure messages.
-   Generate a readable HTML report and execution log.
-   Provide repeatable tests and evidence suitable for a portfolio.
-   Keep the implementation feasible on the available hardware and free
    software.

### 7.2 Non-Goals

WINAP V1 will not implement:

-   Multi-server orchestration or remote fleet management.
-   Domain Controller promotion or Active Directory deployment.
-   Hostname changes or automatic renaming.
-   Static IP, DNS, DHCP, routing, or other network reconfiguration.
-   Broad Group Policy or enterprise-wide configuration management.
-   General-purpose vulnerability scanning.
-   Tenable or Qualys API integrations.
-   Automated remediation of multiple security settings.
-   A database, web backend, dashboard, cloud service, or paid
    component.
-   SQL Server administration; this is reserved for a possible future
    extension.

## 8. Functional Requirements

  -----------------------------------------------------------------------
  ID                      Requirement             Priority
  ----------------------- ----------------------- -----------------------
  FR-01                   Validate the supported  Must
                          Windows Server and      
                          PowerShell environment. 

  FR-02                   Load and validate a     Must
                          JSON configuration      
                          file.                   

  FR-03                   Collect inventory,      Must
                          including the current   
                          hostname, without       
                          changing it.            

  FR-04                   Run in audit-first mode Must
                          by default.             

  FR-05                   Support a preview of    Must
                          intended actions.       

  FR-06                   Restrict optional       Must
                          feature installation to 
                          a minimal allowlist.    

  FR-07                   Audit SMBv1 server      Must
                          protocol status.        

  FR-08                   Audit Windows Firewall  Must
                          profile status.         

  FR-09                   Audit selected TLS      Should
                          configuration           
                          indicators, reporting   
                          ambiguity               
                          appropriately.          

  FR-10                   Permit only the         Must
                          approved SMBv1 server   
                          remediation in V1.      

  FR-11                   Require explicit        Must
                          remediation opt-in and  
                          pass safety checks      
                          before attempting a     
                          change.                 

  FR-12                   Revalidate state after  Must
                          an attempted change.    

  FR-13                   Write execution logs    Must
                          and generate an HTML    
                          report.                 

  FR-14                   Report errors, skipped  Must
                          checks, and unverified  
                          results clearly.        

  FR-15                   Use compatible Pester   Must
                          tests if installation   
                          and compatibility       
                          checks succeed;         
                          otherwise use a         
                          built-in minimal test   
                          harness.                
  -----------------------------------------------------------------------

### 8.1 Minimal Feature Allowlist

Feature management must use an explicit allowlist containing only the
small set of Windows Server roles or features selected for the approved
baseline.

The configuration must not be allowed to request arbitrary feature names
and have WINAP install them automatically. Requested items must be
checked against the allowlist before any installation command is
considered.

The initial implementation should keep this list small. A feature should
be included only if it has a clear demonstration purpose, is supported
by the lab environment, and does not require additional infrastructure
that would make V1 unnecessarily complex.

The final list of feature names must be verified against the actual
Windows Server 2022 installation before implementation. No feature is to
be installed merely because it appears in an example configuration.

## 9. Non-Functional Requirements

### 9.1 Safety

-   Audit-only behavior is the default.
-   Changes require explicit operator intent.
-   Unsupported or ambiguous states must not trigger automatic
    remediation.
-   No automatic reboot.
-   No hostname, network, domain, or broad security-policy changes.
-   The remediation engine must not expand beyond the approved SMBv1
    server protocol scope in V1.

### 9.2 Reliability

-   Validate input before making changes.
-   Handle missing commands, permission problems, invalid configuration,
    and command failures.
-   Distinguish Pass, Fail, Warning, Skipped, and Error outcomes where
    appropriate.
-   Do not report success when a result cannot be verified.

### 9.3 Maintainability

-   Keep responsibilities separated into focused functions or module
    components.
-   Avoid duplicated logic and unnecessary abstractions.
-   Use descriptive names and comments where they clarify non-obvious
    decisions.
-   Keep the design understandable to a junior Windows infrastructure
    engineer.

### 9.4 Performance and Resource Use

-   Operate locally on one VM.
-   Avoid unnecessary background services and persistent processes.
-   Avoid heavyweight dependencies.
-   Use modest memory and disk resources.

### 9.5 Portability

The initial target is Windows Server 2022 with Windows PowerShell 5.1.
The implementation must verify the actual environment rather than
assuming that every required cmdlet or feature is available.

## 10. User Stories and Use Cases

### 10.1 User Stories

-   As an operator, I want to audit a server without changing it so that
    I can understand its current state safely.
-   As an operator, I want a preview of planned actions before
    execution.
-   As an operator, I want feature management restricted to an approved
    list.
-   As an operator, I want SMBv1 server remediation to be explicitly
    requested and guarded by safety checks.
-   As an operator, I want the report to distinguish successful checks,
    failed checks, skipped actions, and errors.
-   As a reviewer, I want clear documentation, test evidence, and an
    understandable repository structure.

### 10.2 Core Use Cases

#### Use Case A --- Audit Only

The operator runs WINAP without remediation. The tool validates its
configuration, inventories the server, evaluates the supported checks,
and generates a report without intentionally changing system
configuration.

#### Use Case B --- Preview

The operator requests preview mode. WINAP shows the actions that would
be considered, including any requested allowlisted feature operation or
eligible SMBv1 remediation, without applying those actions.

#### Use Case C --- Approved Feature Management

The operator explicitly enables feature management. WINAP rejects
unapproved feature names, checks feature state, and installs only
approved features that are not already installed and whose installation
is permitted by the validated configuration.

#### Use Case D --- SMBv1 Remediation

The operator explicitly requests remediation. WINAP checks its
environment and the SMBv1 server configuration, evaluates the defined
safety conditions, and attempts to disable the SMBv1 server protocol
only when those conditions pass. It then rechecks the resulting state.

#### Use Case E --- Error Reporting

A check or command fails. WINAP records the failure and includes the
relevant status in its log and report instead of falsely marking the run
as successful.

## 11. Configuration Design

The project will use a JSON configuration file for supported options.
The file will be validated before execution.

The following is a conceptual example only. The final schema and
approved feature names must be confirmed before implementation.

``` json
{
  "execution": {
    "mode": "Audit",
    "allowFeatureManagement": false,
    "allowRemediation": false
  },
  "inventory": {
    "collectHostname": true,
    "changeHostname": false
  },
  "features": {
    "allowlist": []
  },
  "securityChecks": {
    "smb1ServerProtocol": true,
    "firewallProfiles": true,
    "tlsIndicators": true
  },
  "remediation": {
    "smb1ServerProtocol": {
      "enabled": false,
      "requireSafetyValidation": true
    }
  },
  "reporting": {
    "format": "HTML",
    "includeExecutionLog": true
  }
}
```

### 11.1 Configuration Rules

-   Audit mode must remain the default.
-   Remediation must remain disabled unless explicitly enabled by the
    operator.
-   The `changeHostname` setting must remain `false`; hostname changes
    are not implemented in V1.
-   Only the final approved feature allowlist may be used.
-   Unknown or unsupported configuration keys must be handled
    consistently and documented.
-   Invalid configuration must stop execution before
    configuration-changing operations.
-   Example settings do not override the safety rules defined in this
    document.

## 12. Security and Remediation Design

### 12.1 SMBv1 Server Protocol --- The Only V1 Remediation Target

WINAP may attempt to disable the SMBv1 server protocol. It must not
change SMBv1 client settings, and it must not add other remediation
targets in V1.

The design must include the following safety gates:

1.  Verify the operating system, PowerShell environment, required
    cmdlets, and administrative permissions.
2.  Confirm that remediation was explicitly requested and is enabled by
    the validated configuration.
3.  Read the current SMB server configuration using a supported
    mechanism, such as `Get-SmbServerConfiguration`, when available.
4.  Confirm that the relevant SMBv1 server setting can be read and
    interpreted reliably.
5.  Check for an already-disabled state and report it without making an
    unnecessary change.
6.  If the state is unsupported, unavailable, ambiguous, or
    inconsistent, skip remediation and explain why.
7.  Require the operator to acknowledge that disabling SMBv1 may affect
    legacy systems or applications that depend on it. The lab should be
    isolated and have no unassessed production dependencies.
8.  Attempt the change only when all required preconditions pass, using
    a supported Windows Server mechanism.
9.  Re-read the setting and report whether the intended state was
    verified.
10. If the command fails or the post-check cannot confirm the state,
    report the outcome as failed or unverified---not successful.

WINAP cannot reliably prove the absence of all legacy dependencies from
a configuration query alone. Therefore, automated checks are not a
substitute for an operator's dependency and impact assessment. If the
safety conditions cannot be established, the correct result is to skip
remediation.

No automatic reboot or unrelated security changes are permitted.

### 12.2 Windows Firewall Profiles --- Audit Only

WINAP will inspect the relevant Windows Firewall profiles and report
whether their state meets the defined baseline.

Firewall changes are out of scope for V1. The tool must not change
firewall profiles, rules, or network access.

### 12.3 TLS Indicators --- Audit Only

WINAP may inspect a narrowly defined set of TLS registry/configuration
indicators and report findings.

Registry values can be absent, inherited, or dependent on OS defaults
and policy. An absent value must not automatically be interpreted as
proof that a protocol is enabled or disabled. Ambiguous results must be
identified as warnings or unknown states.

WINAP will not change TLS registry values in V1.

### 12.4 Feature Installation Safety

Feature installation must be explicitly enabled, limited to the approved
allowlist, and checked against the current installation state. WINAP
must not perform arbitrary role or feature installation from untrusted
configuration input.

## 13. Validation, Logging, and Reporting

### 13.1 Validation

Validation must cover:

-   Configuration syntax and required values.
-   Environment and command availability.
-   Administrative permissions where required.
-   Feature names and allowlist membership.
-   Current configuration state before an approved action.
-   Resulting state after an attempted change.
-   Report generation and output-file handling.

### 13.2 Logging

The execution log should record:

-   Run timestamp and execution mode.
-   Relevant environment and inventory information.
-   Checks performed and their outcomes.
-   Actions considered, skipped, or attempted.
-   Errors and relevant diagnostic details.
-   Whether post-action verification succeeded.

Logs must avoid storing credentials, secrets, or unnecessary sensitive
information.

### 13.3 HTML Report

The report should be standalone and readable in a normal browser. It
should contain:

-   Run summary and timestamp.
-   Server inventory, including hostname as collected information.
-   Execution mode.
-   Check results and their statuses.
-   Feature-management results, if enabled.
-   Remediation eligibility, attempted action, and verification outcome,
    if applicable.
-   Warnings, skipped checks, and errors.
-   Log-file location.

The report must clearly distinguish an audit finding from an attempted
remediation and from a verified final state.

## 14. Testing Strategy

### 14.1 Pester Preference and Compatibility Gate

WINAP will use Pester only if installation and compatibility checks
succeed in the target environment.

Before adopting it, the implementation phase must verify:

-   The available PowerShell version.
-   The installed or installable Pester version and its compatibility
    with that PowerShell environment.
-   Whether installation is possible without paid services or an
    account-dependent trial.
-   Whether the selected installation method is suitable for the
    isolated lab and available resources.

No particular Pester version is assumed in this draft. The version and
installation procedure must be determined from the actual environment
and verified documentation.

If Pester cannot be installed or its compatibility cannot be
established, WINAP will use a small built-in PowerShell test harness.
Testing must not be abandoned because a dependency is unavailable.

### 14.2 Test Coverage

Tests should cover:

-   Valid and invalid JSON configuration.
-   Default audit-only behavior.
-   Rejection of feature names outside the allowlist.
-   Inventory collection without hostname changes.
-   Handling of missing commands and insufficient permissions.
-   SMBv1 remediation being blocked when opt-in is absent.
-   SMBv1 remediation being skipped when preflight or state validation
    fails.
-   Correct handling of the already-disabled state.
-   Correct handling of failed or unverified post-checks.
-   Audit-only handling of firewall and TLS checks.
-   Log and HTML report generation.
-   Error reporting and overall run status.

### 14.3 Test Safety

Destructive or configuration-changing tests must not be run against a
production system. Tests that would change the SMB server configuration
must be restricted to the isolated lab VM and conducted only after
reviewing the impact.

Where practical, unit tests should isolate decision logic from actual
system-changing cmdlets. Integration tests must verify the behavior
against the real lab environment.

## 15. Proposed Repository Structure

The repository should remain compact and understandable.

``` text
WINAP/
├── config/
│   └── baseline.example.json
├── docs/
│   └── TDD.md
├── src/
│   ├── Invoke-WINAP.ps1
│   └── WINAP/
│       ├── WINAP.psm1
│       └── Private/
│           ├── Configuration.ps1
│           ├── Inventory.ps1
│           ├── FeatureManagement.ps1
│           ├── Audit.ps1
│           ├── Remediation.ps1
│           ├── Logging.ps1
│           └── Reporting.ps1
├── tests/
│   └── WINAP.Tests.ps1
├── examples/
│   └── reports/
├── evidence/
├── CHANGELOG.md
├── .gitignore
└── LICENSE
```

This is a proposed structure, not an instruction to create files now.
The exact module boundaries may be simplified during implementation if
that preserves clarity and safety.

`README.md` is intentionally omitted from the development phases. It
will be created once, after V1 has been built, tested, and verified as
functional.

Generated logs and reports must be handled deliberately in `.gitignore`;
only sanitized, useful demonstration evidence should be committed.

## 16. Assumptions and Constraints

### 16.1 Assumptions

-   A Windows 11 host is available.
-   VMware Workstation is installed.
-   A Windows Server 2022 ISO is available.
-   One Windows Server 2022 VM can be allocated approximately 3 GB RAM,
    subject to observed host and VM performance.
-   The operator can access the VM with the permissions required for the
    selected checks.
-   The project will be run in an isolated, non-production environment.
-   The project is for demonstration and learning, not production
    deployment.

### 16.2 Constraints

-   The host has 8 GB RAM and an Intel i5-1235U processor.
-   The project should avoid running multiple heavy VMs simultaneously.
-   No paid products, subscriptions, or free-trial dependencies.
-   No backend, database, cloud service, or web dashboard.
-   No automatic hostname, IP, DNS, domain, firewall, or TLS changes.
-   Only one V1 remediation target: SMBv1 server protocol, guarded by
    safety validation.
-   SQL Server administration remains a potential V2 learning extension,
    not part of V1.

## 17. Risks and Mitigations

  -----------------------------------------------------------------------
  Risk                                Mitigation
  ----------------------------------- -----------------------------------
  SMBv1 is required by a legacy       Require impact assessment and
  dependency.                         safety validation; skip remediation
                                      if the situation is unclear.

  A configuration value is missing or Report unknown or warning states
  ambiguous.                          rather than guessing.

  An arbitrary feature is requested   Validate against the minimal
  in JSON.                            allowlist before any installation.

  Pester is incompatible or           Verify compatibility first; use the
  unavailable.                        built-in test harness as a
                                      fallback.

  A command fails partway through     Log the failure, verify resulting
  execution.                          state where possible, and report
                                      accurately.

  The VM is resource constrained.     Keep the implementation local,
                                      modular, and dependency-light; test
                                      on one VM.

  A report incorrectly suggests       Require explicit result states and
  success.                            post-action verification.

  The project expands beyond a        Defer multi-server support, extra
  weekend-sized scope.                remediation, APIs, databases,
                                      dashboards, and SQL Server
                                      integration.

  A feature installation requires a   Do not reboot automatically; report
  reboot.                             any requirement and leave reboot
                                      decisions to the operator.

  Sensitive data appears in logs or   Exclude credentials and unnecessary
  reports.                            sensitive information; review
                                      demonstration evidence before
                                      committing.
  -----------------------------------------------------------------------

## 18. Success Criteria and Acceptance Criteria

WINAP V1 is acceptable when all of the following are demonstrated:

-   It runs on the verified Windows Server 2022 lab environment using
    the selected supported PowerShell version.
-   It validates configuration and clearly rejects invalid input.
-   It collects inventory without changing the hostname.
-   It defaults to audit-only behavior.
-   It can preview intended operations without applying them.
-   Feature management is limited to the final approved minimal
    allowlist.
-   Firewall and TLS checks are audit-only.
-   SMBv1 server remediation is the only implemented remediation target.
-   SMBv1 remediation requires explicit opt-in and passes the defined
    safety gates.
-   The tool correctly handles already-disabled, unsupported, ambiguous,
    failed, and unverified states.
-   No automatic reboot or unrelated system change occurs.
-   Logs and a standalone HTML report are generated.
-   Tests run through compatible Pester when verified available, or
    through the built-in harness otherwise.
-   The completed project includes test evidence, a changelog,
    meaningful Git commits and tags, and final documentation.
-   The final README is created only after the full project is built and
    verified.
-   The project can be explained and demonstrated without overstating it
    as a production platform or certified vulnerability scanner.

## 19. Delivery Plan and Git Checkpoints

The work will proceed only after approval of this TDD. Each
implementation phase will have explicit instructions, verification
steps, and a checkpoint.

  -----------------------------------------------------------------------
  Phase                   Scope                   Required checkpoint
  ----------------------- ----------------------- -----------------------
  0                       Review and approve the  Explicit approval
                          TDD.                    before implementation
                                                  begins.

  1                       Verify the environment, Environment checks and
                          create the repository   repository
                          skeleton, and establish verification.
                          the baseline Git state. 

  2                       Implement configuration Valid/invalid
                          loading, validation,    configuration tests;
                          and inventory           confirm hostname is
                          collection.             read-only.

  3                       Implement audit         Audit and allowlist
                          functions and the       tests; verify no
                          minimal feature         unapproved feature can
                          allowlist.              be installed.

  4                       Implement the SMBv1     Test opt-in,
                          server remediation      preconditions,
                          safety gate and         already-disabled state,
                          narrowly scoped action. failures, and
                                                  post-check behavior in
                                                  the lab.

  5                       Implement logging,      Verify reports, logs,
                          status handling, and    and error outcomes.
                          HTML reporting.         

  6                       Complete integration    Run the full test suite
                          tests, compatibility    and demonstrate the
                          verification, and       acceptance criteria.
                          end-to-end validation.  

  7                       Finalize sanitized      Final functional
                          evidence, review the    verification and
                          changelog and Git       explicit release
                          history, create         checkpoint.
                          `README.md`, and        
                          prepare the V1 release. 
  -----------------------------------------------------------------------

### 19.1 Git Requirements

After each completed phase:

-   Update `CHANGELOG.md`.
-   Provide the proposed commit message.
-   Provide the proposed annotated Git tag.
-   Verify the changed files and test results.
-   Confirm the working tree and Git history are in the expected state.
-   Stop at the checkpoint and wait for authorization before proceeding
    to the next phase.

No Git push or publication should occur without explicit approval. The
exact tag names and commit messages will be proposed at the relevant
phase checkpoints rather than treated as completed work in this draft.

## 20. Estimated Effort

The target is a weekend-sized project, estimated at approximately 11--18
focused hours, depending on VM setup, PowerShell compatibility, test
coverage, and debugging. This is an estimate rather than a guarantee.
Safe implementation and verification take precedence over meeting the
time target.

## 21. Future Enhancements --- Explicitly Outside V1

Potential future extensions may include:

-   Additional audited security baseline checks.
-   Additional remediation targets with independent safety reviews.
-   Broader feature profiles.
-   More extensive evidence and report formatting.
-   A separate SQL Server administration learning extension after WINAP
    V1.

These enhancements are not approved for V1 and must not be added during
implementation without revising and approving the scope.

