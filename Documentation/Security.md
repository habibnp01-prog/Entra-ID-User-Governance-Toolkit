\# Security Considerations



This toolkit can perform administrative operations against Microsoft Entra ID.



It should therefore be treated as an administrative security tool.



\---



\## Security Principles



The project follows these principles:



\- Least privilege

\- Read-only discovery

\- Explicit approval

\- WhatIf support

\- Live state revalidation

\- Audit logging

\- No uncontrolled bulk remediation

\- Separation of discovery and remediation



\---



\## Credentials



Do not store:



\- Passwords

\- Access tokens

\- Refresh tokens

\- Client secrets

\- Certificates

\- Private keys



inside the repository.



\---



\## Tenant Information



Avoid committing production tenant information unless it is intentionally documented and considered safe for publication.



Generated reports may contain:



\- User principal names

\- Employee information

\- Department information

\- Role assignments

\- License information

\- Group information

\- Tenant information



Generated reports are therefore excluded from source control.



\---



\## Audit Logs



Audit logs may contain sensitive administrative information.



Do not commit:



```text

Logs\\\*.csv

Logs\\\*.log

