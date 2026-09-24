# ServiceNow application health scan

Edit `appNames` near the top of `Scripts/USEM_HC_ApplicationHealthScan.js` with the application scope names (`sys_scope.scope`), not display labels:

```javascript
var appNames = ['sn_sec_cmn'];
// Or scan several applications in one run:
var appNames = ['sn_sec_cmn', 'sn_vul'];
```

Run the script as an administrator in your ServiceNow server-side script environment with read access to the selected scopes and Customer Updates metadata. Each application's output starts with its scope name and scope sys_id. All findings below that header belong to that application until the next header. Blank and duplicate scope entries are ignored; missing or ambiguous applications are reported and skipped.

The scan covers Client Scripts, Business Rules, UI Actions, Script Includes, and Scheduled Script Executions. Only tables with findings and nonzero counters appear. Empty detail sections are omitted. An application with no findings gets one `No findings.` line. Warnings and skipped-table notices remain visible. `Records scanned` counts only qualifying customer-created or customer-modified records; untouched OOB records are excluded before any finding checks.

## Editable finding notes

Edit `findingGuidance` near the top of the script, immediately after `appNames`. Each check has a `why` sentence and an `alternative` sentence. The report prints both beneath **each finding**, including low-priority modified-OOB findings. Change the wording in that configuration block; no scan logic needs to change. Empty sections and operational warnings do not print these finding-specific notes.

| Configuration key | Check |
| --- | --- |
| `sysIds` | Hardcoded sys_ids |
| `gsInfo` | gs.info() logging |
| `grVariables` | Exact-gr variable declarations |
| `currentUpdate` | current.update() in Business Rules |
| `inactiveRunAs` | Inactive scheduled-job Run as user |

The defaults are concise summaries of ServiceNow guidance, with practical review suggestions:

- Hardcoded IDs, variable names/scope, and recursive Business Rules: [ServiceNow scripting and Business Rule best practices](https://developer.servicenow.com/print_page.do?category=now-platform&identifier=business_rules_technical_best_practices&module=guide&release=zurich).
- Logging: [GlideSystem info/debug APIs](https://www.servicenow.com/docs/r/api-reference/server-api-reference/c_GlideSystemScopedAPI.html) and the [documented excessive gs.info logging issue PRB1968412](https://www.servicenow.com/docs/r/release-notes/australia-all-other-fixes.html). Useful operational info logs are not automatically defects.
- Inactive execution accounts: [Impact Manageability check sn_SE10454](https://www.servicenow.com/docs/r/impact/scan-engine-definitions-manageability.html). Review the job's supported account configuration; inactivity does not prove the job stopped running.

## Exact-gr rule

The variable check flags declarations whose entire variable name is `gr`, case-insensitively: `var gr`, `let GR`, `const Gr`, and `var gR`. Descriptive names such as `grMembers`, `grTask`, `gr_task`, `gr1`, and `gr$` are allowed. Like the original check, this is a static pattern check for names immediately following `var`, `let`, or `const`, not a JavaScript parser. Matches in comments or strings require review; it does not enumerate parameters or every possible declaration form.

## Record selection and priorities

The same filter and priority policy applies to **every check**: hard-coded sys_ids, `gs.info()`, exact-gr declarations, Business Rule `current.update()`, and inactive scheduled-job Run as users.

| Record category | Report behavior |
| --- | --- |
| Unmodified OOB | Excluded from all checks and output, even if it contains exact-gr or other patterns |
| Customized OOB/Store file | Include findings with `Low` priority and `note: finding may be inherited from OOB` |
| Custom Created | Include all findings with `High` priority |

A record qualifies through a true `sys_customer_update` marker or a matching local `sys_update_xml` entry in the `customer` category whose latest action is `INSERT`, `UPDATE`, or `INSERT_OR_UPDATE`. Lookup uses `sys_update_name` when available, otherwise `<record class/table>_<sys_id>`. Records without customer-change evidence are excluded before every check. Retrieved/preview-only updates, internal updates, and deletion-only evidence do not qualify. Committed remote updates have local update-set copies. Required customer-update metadata must be available or the scan stops.

For qualifying records, an exact-name version from `sys_upgrade_history` or `sys_store_app` establishes the **Customized OOB/Store file** label. Otherwise, the requested reporting policy labels the record **Custom Created**, including when version metadata is missing or inaccessible. Every finding includes the record sys_id, origin, and priority. These are code-review priorities, not exploitability ratings.

`Custom Created` is a reporting assumption when origin evidence is incomplete, not proof of authorship. Missing history can classify a modified OOB file as Custom Created; custom files without customer-change evidence are excluded. Reverted files with retained customer-change evidence may still qualify. The scan does not compare current code byte-for-byte with the baseline, which is why modified-OOB findings explicitly say they may be inherited from OOB.

Example layout (placeholder IDs):

```text
Application: sn_sec_cmn | Scope sys_id: <application_sys_id> | Records scanned: 2
sys_script_include | Exact "gr" declarations: 2
Exact "gr" declarations:
  sys_script_include | Custom example | record: <record_sys_id> | origin: Custom Created | priority: High | exact-gr declarations: 1 | names: gr
    Why: <one-sentence concern from findingGuidance.grVariables>
    Suggested alternative: <one-sentence fix from findingGuidance.grVariables>
  sys_script_include | OOB example | record: <other_record_sys_id> | origin: Customized OOB/Store file | priority: Low | note: finding may be inherited from OOB | exact-gr declarations: 1 | names: gr
    Why: <one-sentence concern from findingGuidance.grVariables>
    Suggested alternative: <one-sentence fix from findingGuidance.grVariables>
```

ServiceNow references: [Customer Updates](https://www.servicenow.com/docs/r/platform-security/r_CustomerUpdatesTable.html), [customized objects and actions](https://www.servicenow.com/docs/r/yokohama/application-development/system-update-sets/view-customer-update-records.html), [update-name conventions](https://www.servicenow.com/docs/r/zurich/application-development/system-update-sets/t_CompareLocalUpdateSets.html), [committed update sets create local copies](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_CommitAnUpdateSet.html), and [Version records](https://www.servicenow.com/docs/r/application-development/team-development/r_VersionRecords.html). The delivery-source checks also appear in this [ServiceNow Community author's implementation](https://www.servicenow.com/community/developer-articles/my-collected-list-of-useful-business-rules/ta-p/2467239).

## Local validation

Tests use mocked ServiceNow APIs; live instance validation is still needed.

```sh
node --check Scripts/USEM_HC_ApplicationHealthScan.js
node tests/application-health-scan.test.js
```
