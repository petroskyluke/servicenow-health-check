# ServiceNow application health scan

Edit `appNames` near the top of `Scripts/USEM_HC_ApplicationHealthScan.js` with the application scope names (`sys_scope.scope`), not display labels:

```javascript
var appNames = ['sn_sec_cmn'];
// Or scan several applications in one run:
var appNames = ['sn_sec_cmn', 'sn_vul'];
```

Run the script as an administrator in your ServiceNow server-side script environment with read access to the selected scopes and Customer Updates metadata. Each application's output starts with its scope name and scope sys_id. All findings below that header belong to that application until the next header. Blank and duplicate scope entries are ignored; missing or ambiguous applications are reported and skipped.

The scan covers Client Scripts, Business Rules, UI Actions, Script Includes, and Scheduled Script Executions. Only tables with findings and nonzero counters appear. Empty detail sections are omitted. An application with no findings gets one `No findings.` line. Warnings and skipped-table notices remain visible. `Records scanned` counts the records examined within the selected scope, including records checked only for exact-gr declarations.

## Exact-gr rule and priorities

The variable check flags declarations whose entire variable name is `gr`, case-insensitively: `var gr`, `let GR`, `const Gr`, and `var gR`. Descriptive names such as `grMembers`, `grTask`, `gr_task`, `gr1`, and `gr$` are allowed. Like the original check, this is a static pattern check for names immediately following `var`, `let`, or `const`, not a JavaScript parser. Matches in comments or strings require review; it does not enumerate parameters or every possible declaration form.

This check runs on **all records in the selected scopes**, including untouched OOB files. Each exact-gr finding includes a priority:

| Reporting origin | Exact-gr priority |
| --- | --- |
| UPMC custom | SEVERE |
| Customized OOB/Store file | LOW |
| OOB/Store file, including files with no tracked customer changes | LOW |

These are the requested code-review priorities, not exploitability ratings. Each detail line carries its record sys_id, origin, priority, occurrence count, and matched variable names.

## Other checks and origin labels

Hard-coded sys_ids, `gs.info()`, Business Rule `current.update()`, and inactive scheduled-job Run as users retain their customer-record filter. A record qualifies through a true `sys_customer_update` marker or a matching local `sys_update_xml` entry in the `customer` category whose latest action is `INSERT`, `UPDATE`, or `INSERT_OR_UPDATE`. Lookup uses `sys_update_name` when available, otherwise `<record class/table>_<sys_id>`. Retrieved/preview-only updates, internal updates, and deletion-only evidence do not qualify for these checks. Committed remote updates have local update-set copies. Required customer-update metadata must be available or the scan stops.

Reporting origins follow the requested UPMC policy:

- **Customized OOB/Store file:** customer-change evidence plus an exact-name version from `sys_upgrade_history` or `sys_store_app`.
- **OOB/Store file:** delivery baseline exists, with no tracked customer changes. These files are included only for exact-gr findings.
- **OOB/Store (no customer changes tracked):** no customer-change evidence or delivery baseline is available. These files are included only for exact-gr findings, at LOW priority.
- **UPMC custom:** customer-change evidence exists and no delivery baseline is found or accessible. This replaces the former unresolved-origin and likely-customer-created labels, and exact-gr findings receive SEVERE priority.

The fallback labels are reporting assumptions selected by the user, not proof of authorship. Missing or purged history can route a modified OOB file to UPMC custom, or an untracked custom file to LOW-priority OOB review. Reverted files with retained customer-change evidence may still qualify. This scan does not compare current code byte-for-byte with the baseline.

Example layout (placeholder IDs):

```text
Application: sn_sec_cmn | Scope sys_id: <application_sys_id> | Records scanned: 12
sys_script_include | Exact "gr" declarations: 2
Exact "gr" declarations:
  sys_script_include | UPMC example | record: <record_sys_id> | origin: UPMC custom | priority: SEVERE | exact-gr declarations: 1 | names: gr
  sys_script_include | OOB example | record: <other_record_sys_id> | origin: OOB/Store file | priority: LOW | exact-gr declarations: 1 | names: gr
```

ServiceNow references: [Customer Updates](https://www.servicenow.com/docs/r/platform-security/r_CustomerUpdatesTable.html), [customized objects and actions](https://www.servicenow.com/docs/r/yokohama/application-development/system-update-sets/view-customer-update-records.html), [update-name conventions](https://www.servicenow.com/docs/r/zurich/application-development/system-update-sets/t_CompareLocalUpdateSets.html), [committed update sets create local copies](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_CommitAnUpdateSet.html), and [Version records](https://www.servicenow.com/docs/r/application-development/team-development/r_VersionRecords.html). The delivery-source checks also appear in this [ServiceNow Community author's implementation](https://www.servicenow.com/community/developer-articles/my-collected-list-of-useful-business-rules/ta-p/2467239).

## Local validation

Tests use mocked ServiceNow APIs; live instance validation is still needed.

```sh
node --check Scripts/USEM_HC_ApplicationHealthScan.js
node tests/application-health-scan.test.js
```
