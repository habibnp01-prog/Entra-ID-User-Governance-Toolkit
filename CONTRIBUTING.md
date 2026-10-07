\# Contributing



Thank you for your interest in contributing to the Entra ID User Governance Toolkit.



Contributions are welcome, particularly around:



\- PowerShell improvements

\- Microsoft Graph integration

\- Microsoft Entra ID governance

\- Security improvements

\- Testing

\- Documentation

\- Reporting

\- Error handling



\---



\## Before Contributing



Please:



1\. Read the README.

2\. Review the architecture documentation.

3\. Understand the security model.

4\. Test changes in a non-production environment.

5\. Do not commit tenant-specific information.

6\. Do not commit credentials, tokens, or production audit logs.



\---



\## Development Guidelines



\### PowerShell



Prefer:



\- Clear function names

\- Explicit parameters

\- Error handling

\- `SupportsShouldProcess` for modifying operations

\- WhatIf support where appropriate

\- Meaningful output

\- Live state revalidation before high-impact changes

\- Audit logging for administrative changes



Avoid:



\- Hard-coded credentials

\- Hard-coded tenant secrets

\- Uncontrolled bulk modifications

\- Silent destructive operations



\---



\## Pull Requests



Pull requests should include:



\- Description of the change

\- Reason for the change

\- Testing performed

\- Any required permission changes

\- Security considerations



\---



\## Testing



All changes should be tested before submission.



Where applicable, test:



\- Normal execution

\- WhatIf execution

\- Invalid input

\- Missing data

\- Permission failures

\- Microsoft Graph API failures

\- Empty result sets

\- Existing report and log files



\---



\## Security



If you discover a security issue, do not publish sensitive details in a public issue.



Use the repository's configured security contact or private disclosure mechanism where available.

