# Test Plan

## Test Environment

The toolkit was validated using:

- Operating System: Windows
- PowerShell: Windows PowerShell 5.1
- Microsoft Graph PowerShell SDK: 2.41.1
- Identity Platform: Microsoft Entra ID

---

## Discovery Tests

### User Discovery

Expected:

- Users retrieved successfully
- User properties populated
- Account state identified
- License information retrieved
- Sign-in information processed

Result: **PASS**

### Inactive User Detection

Expected:

- Inactivity threshold applied
- Active users classified correctly
- Inactive users identified
- Never-signed-in users identified
- Disabled users classified separately

Result: **PASS**

### Expired User Detection

Expected:

- `employeeLeaveDateTime` evaluated
- Expired enabled users identified
- Expired disabled users identified
- Upcoming leavers identified
- Users without leave dates handled

Result: **PASS**

### Guest User Detection

Expected:

- Guest accounts identified
- Activity evaluated
- Empty guest populations handled correctly

Result: **PASS**

### Disabled User Detection

Expected:

- Disabled accounts identified
- Licensed disabled accounts identified
- Expired disabled accounts identified
- Governance candidates identified

Result: **PASS**

### License Governance

Expected:

- Licensed users identified
- Inactive licensed users identified
- Expired licensed users identified
- Disabled licensed users identified
- Governance priorities calculated

Result: **PASS**

### Privileged Role Analysis

Expected:

- Directory role assignments retrieved
- User principals resolved
- Non-user principals handled
- Service principals distinguished
- Governance classifications generated

Result: **PASS**

### Group Membership Analysis

Expected:

- Direct group memberships retrieved
- Group types classified
- Thresholds evaluated
- Users without direct membership handled

Result: **PASS**

---

## Review Tests

The review workflow was tested for:

- Summary
- Candidate listing
- User search
- User inspection
- Full user listing
- Report export
- Exit handling

Result: **PASS**

---

## Remediation Tests

### WhatIf

Expected:

- Proposed action displayed
- No Entra ID modification
- No unintended changes

Result: **PASS**

### Controlled User Disablement

Expected:

- User selected explicitly
- Governance findings displayed
- Confirmation requested
- Current state revalidated
- User disabled
- Audit event created

Result: **PASS**

### License Removal

High-impact license removal should be validated separately in a controlled test environment.

### Group Membership Removal

High-impact group membership removal should be validated separately in a controlled test environment.

---

## Audit Tests

Expected:

- Audit log created
- Events contain unique IDs
- Timestamps recorded
- Actions recorded
- Results recorded
- Administrator information recorded

Result: **PASS**

---

## Reporting Tests

Expected:

- Governance CSV generated
- Governance HTML generated
- Findings consolidated
- Priorities calculated
- Remediation status correlated
- Last remediation action displayed

Result: **PASS**

---

## Final Validation

The implemented discovery, review, remediation, audit, and reporting workflows passed functional validation.

No uncontrolled bulk remediation was performed.

High-impact remediation actions should continue to be tested independently in a controlled environment before production use.
