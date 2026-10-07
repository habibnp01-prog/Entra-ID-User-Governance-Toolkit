\# Changelog



All notable changes to the Entra ID User Governance Toolkit are documented in this file.



\---



\## \[1.0.0] - 2026-10-07



\### Added



\- Entra ID user discovery

\- Inactive user detection

\- Expired user detection

\- Guest user governance

\- Disabled user governance

\- License governance analysis

\- Privileged role analysis

\- Direct group membership analysis

\- Interactive governance review

\- Controlled remediation workflow

\- WhatIf support

\- Administrator confirmation controls

\- Live state revalidation before remediation

\- Audit logging

\- CSV governance reporting

\- HTML governance reporting

\- Remediation status correlation



\### Security



\- Read-only discovery workflow

\- Explicit administrator approval for remediation

\- Additional confirmation for high-impact actions

\- No uncontrolled bulk remediation

\- Audit trail for administrative changes

\- Separation of discovery and remediation

\- Least-privilege permission documentation



\### Validation



Validated using:



\- Windows PowerShell 5.1

\- Microsoft Graph PowerShell SDK 2.41.1

\- Microsoft Entra ID test environment



All implemented discovery, review, remediation, audit, and reporting workflows passed functional validation.



High-impact license and group membership remediation should be validated separately in a controlled environment before production use.

