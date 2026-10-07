\# Microsoft Graph Permissions



The toolkit uses Microsoft Graph PowerShell SDK permissions according to the operation being performed.



Permissions should be granted only to administrators who require the associated functionality.



\---



\## Permission Matrix



| Script | Purpose | Primary Permissions |

|---|---|---|

| 01 | User discovery | User.Read.All, AuditLog.Read.All |

| 02 | Inactive users | User.Read.All, AuditLog.Read.All |

| 03 | Expired users | User.Read.All |

| 04 | Guest users | User.Read.All, AuditLog.Read.All |

| 05 | Disabled users | User.Read.All, AuditLog.Read.All |

| 06 | License governance | User.Read.All, AuditLog.Read.All |

| 07 | Privileged users | User.Read.All, RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All |

| 08 | Group membership | User.Read.All, Group.Read.All, Directory.Read.All |

| 09 | Review | Local governance reports |

| 10 | Remediation | User.Read.All, User.ReadWrite.All, Group.Read.All, GroupMember.ReadWrite.All, Directory.Read.All, LicenseAssignment.ReadWriteAll |

| 11 | Audit | Local audit log |

| 12 | Reporting | Local governance reports and audit log |



\---



\## Read-Only Permissions



Most governance discovery operations are read-only.



Examples:



```text

User.Read.All

AuditLog.Read.All

Directory.Read.All

RoleManagement.Read.Directory

Group.Read.All

