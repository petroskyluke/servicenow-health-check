# ServiceNow application health scan

Edit `appNames` near the top of `Scripts/USEM_HC_ApplicationHealthScan.js` with the application scope names (`sys_scope.scope`), not display labels:

```javascript
var appNames = ['sn_sec_cmn'];
// Or scan several applications in one run:
var appNames = ['sn_sec_cmn', 'sn_vul'];
```

Run the script in your ServiceNow server-side script environment with access to the selected scopes and metadata. Each application is queried and reported separately. Blank entries and repeated scope names are ignored. Missing or ambiguous scope names are reported and skipped without stopping other applications.

Only tables with findings and nonzero finding counts appear in the results. Empty detail sections are omitted. An application with no findings gets a short `No findings.` message. Skipped-table notices and warnings remain visible because those checks may be incomplete.

The existing checks and customization filter are preserved: hard-coded sys_ids, `gs.info()`, variables beginning with `gr`, Business Rule `current.update()`, and active scheduled jobs with inactive Run as users. These are static pattern checks, so matches require review. Records are scanned only when the existing `sys_update_version` lookup identifies them as customized.

Local validation (mocked ServiceNow APIs, not a live instance):

```sh
node --check Scripts/USEM_HC_ApplicationHealthScan.js
node tests/application-health-scan.test.js
```
