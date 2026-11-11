# Detection 02: User Added to Administrators Group

MITRE ATT&CK: T1136.001 (Create Account: Local Account), T1098 (Account Manipulation)
Severity: Medium
Log source: Windows Security log, EventCodes 4720 (user created) and 4732 (member added to local group)

## What it detects
A local account was added to the Administrators group. Attackers do this to keep privileged access (persistence) or to escalate privileges.

## SPL
```
index=win_lab source="WinEventLog:Security" EventCode=4732 Group_Name="Administrators"
| table _time, host, Account_Name, Group_Name, Message

The query extracts the member’s SID from the event message because Windows logs local accounts by SID only.
```

## Alert settings
Scheduled every 5 minutes, searching the last 5 minutes. Triggers when results > 0.

## Tuning notes
Windows automatically adds new local users to the Users group, which also generates a 4732 event. Filtering on Group_Name="Administrators" removes that noise.

## Possible false positives
- IT staff legitimately granting admin rights
- Software installers that create service accounts

## L1 triage steps
1. Identify who made the change (the account that performed it) and on which host
2. Check whether it happened during business hours or a change window
3. Look for a 4720 (account creation) just before the group change
4. Check whether the new account was used to log in afterward (EventCode 4624)

## Escalation
Unexpected admin additions, especially right after account creation or outside a change window, go to L2.

## Evidence
![Alert firing](screenshots/02-new-admin-search-results.png)
