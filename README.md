# ServiceNow application health scan

Edit `appNames` near the top of `Scripts/USEM_HC_ApplicationHealthScan.js` with the application scope names (`sys_scope.scope`), not display labels:

```javascript
var appNames = ['sn_sec_cmn'];
// Or scan several applications in one run:
var appNames = ['sn_sec_cmn', 'sn_vul'];
```

Run the script as an administrator in your ServiceNow server-side script environment with read access to the selected scopes and Customer Updates metadata. Each application is queried and reported separately. Blank entries and repeated scope names are ignored. Missing or ambiguous scope names are reported and skipped without stopping other applications.

Only tables with findings and nonzero finding counts appear in the results. Empty detail sections are omitted. An application with no findings gets a short `No findings.` message. Skipped-table notices and warnings remain visible because those checks may be incomplete.

The existing checks are preserved: hard-coded sys_ids, `gs.info()`, variables beginning with `gr`, Business Rule `current.update()`, and active scheduled jobs with inactive Run as users. These are static pattern checks, so matches require review. Within those five tables, the scan includes customer-created files and customer-modified OOB files. It accepts a true `sys_customer_update` marker or a matching local `sys_update_xml` record in the `customer` category whose latest action is `INSERT`, `UPDATE`, or `INSERT_OR_UPDATE`. Lookup uses `sys_update_name` when available, otherwise `<record class/table>_<sys_id>`. Merely having version history, a high modification count, or a particular creator does not qualify a record.

Retrieved/preview-only updates, internal updates, and deletion-only evidence do not qualify. Committed remote update sets are represented by their local copies. The scan stops with a short message if the required Customer Updates table or fields are unavailable.

This is a customer-change metadata filter, not a byte-for-byte comparison with the OOB baseline or an audit of who authored each file. Files imported without change tracking, or with removed tracking metadata and no customer-update marker, cannot be reliably identified and are excluded. A reverted file with retained customer-change evidence can still qualify; confirm it against the baseline when reviewing findings.

ServiceNow references: [Customer Updates](https://www.servicenow.com/docs/r/platform-security/r_CustomerUpdatesTable.html), [customized objects and insert/update actions](https://www.servicenow.com/docs/r/yokohama/application-development/system-update-sets/view-customer-update-records.html), [update-name conventions](https://www.servicenow.com/docs/r/zurich/application-development/system-update-sets/t_CompareLocalUpdateSets.html), and [committed update sets create local copies](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_CommitAnUpdateSet.html).

Local validation (mocked ServiceNow APIs, not a live instance):

```sh
node --check Scripts/USEM_HC_ApplicationHealthScan.js
node tests/application-health-scan.test.js
```
