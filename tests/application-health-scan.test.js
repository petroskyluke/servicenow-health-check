const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../Scripts/USEM_HC_ApplicationHealthScan.js'), 'utf8');
const tables = ['sys_script_client', 'sys_script', 'sys_ui_action', 'sys_script_include', 'sysauto_script'];

function run(apps, data = {}, invalid = [], missingFields = {}, queryErrors = [], scriptSource = source) {
    const output = [], queries = [];
    class GlideRecord {
        constructor(table) { this.table = table; this.filters = []; this.rows = []; this.index = -1; this.limit = Infinity; }
        addQuery(field, operator, value) {
            this.filters.push(arguments.length === 3 ? [field, value, operator] : [field, operator]);
        }
        addNotNullQuery(field) { this.filters.push([field, 'NOT_NULL']); }
        addNullQuery(field) { this.filters.push([field, 'NULL']); }
        orderByDesc(field) { this.sortField = field; }
        setLimit(limit) { this.limit = limit; }
        query() {
            if (queryErrors.includes(this.table)) throw new Error('Query denied');
            queries.push({ table: this.table, filters: this.filters });
            for (const [field] of this.filters) assert.ok(this.isValidField(field), 'Invalid query field: ' + field);
            this.rows = (data[this.table] || []).filter(row => this.filters.every(([k, v, operator]) => {
                if (operator === 'IN') return v.split(',').includes(row[k]);
                if (v === 'NOT_NULL') return row[k] != null && row[k] !== '';
                if (v === 'NULL') return row[k] == null || row[k] === '';
                return row[k] === v;
            }));
            if (this.sortField) this.rows.sort((a, b) => String(b[this.sortField] || '').localeCompare(String(a[this.sortField] || '')));
            this.rows = this.rows.slice(0, this.limit);
        }
        next() { return ++this.index < this.rows.length; }
        hasNext() { return this.index + 1 < this.rows.length; }
        isValid() { return !invalid.includes(this.table); }
        isValidField(field) { return !(missingFields[this.table] || []).includes(field); }
        getValue(field) { return this.rows[this.index][field] ?? ''; }
        getDisplayValue(field) { return this.getValue(field || 'name'); }
        getUniqueValue() { return this.getValue('sys_id'); }
        get(id) { this.addQuery('sys_id', id); this.query(); return this.next(); }
    }
    vm.runInNewContext(scriptSource.replace("var appNames = ['sn_sec_cmn'];", 'var appNames = ' + JSON.stringify(apps) + ';'), {
        GlideRecord, gs: { print: line => output.push(line) }
    });
    return { text: output.join('\n'), queries };
}
const scopes = [
    { sys_id: 'scope-a', scope: 'sn_sec_cmn', name: 'Security Common' },
    { sys_id: 'scope-b', scope: 'sn_vul', name: 'Vulnerability Response' }
];
const record = (sys_id, sys_scope, script, extra = {}) => ({ sys_id, sys_scope, name: sys_id, script, ...extra });
const update = (name, extra = {}) => ({ name, category: 'customer', action: 'INSERT_OR_UPDATE', update_set: 'local-set', sys_updated_on: '2026-09-24 10:00:00', ...extra });
const data = {
    sys_scope: scopes,
    sys_script: [record('rule-a', 'scope-a', 'gs.info("a"); current.update();'), record('rule-b', 'scope-b', 'gs.info("b"); gs.info("c");'), record('foreign', 'other', 'gs.info("outside");')],
    sys_script_client: [record('clean', 'scope-a', 'var value = 1;'), record('uncustomized', 'scope-a', 'gs.info("ignored");')],
    sys_script_include: [record('include-b', 'scope-b', 'var gr; var id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";')],
    sysauto_script: [record('job-b', 'scope-b', '', { active: '1', run_as: 'inactive' })],
    sys_user: [{ sys_id: 'inactive', name: 'Inactive User', active: '0' }],
    sys_update_xml: ['sys_script_rule-a', 'sys_script_rule-b', 'sys_script_foreign', 'sys_script_client_clean', 'sys_script_include_include-b', 'sysauto_script_job-b'].map(name => update(name))
};
let result = run([' sn_sec_cmn ', 'missing', 'sn_vul', 'sn_sec_cmn', ''], data);
assert.equal((result.text.match(/Application: sn_sec_cmn/g) || []).length, 1);
assert.match(result.text, /Application not found: missing/);
assert.match(result.text, /Application: sn_vul/);
assert.match(result.text, /sys_script \| gs.info\(\): 1 \| current.update\(\): 1/);
assert.match(result.text, /sys_script \| gs.info\(\): 2\n/);
assert.match(result.text, /hard-coded sys_ids: 1 \| Exact "gr" declarations: 1/);
assert.match(result.text, /inactive Run as users: 1/);
assert.doesNotMatch(result.text, /foreign|uncustomized|sys_script_client|sys_ui_action|OVERALL SUMMARY/);
assert.ok(result.queries.filter(q => q.table === 'sys_scope').every(q => q.filters[0][0] === 'scope'));
assert.ok(result.queries.filter(q => tables.includes(q.table)).every(q => q.filters.some(([k, v]) => k === 'sys_scope' && ['scope-a', 'scope-b'].includes(v))));
result = run(['sn_sec_cmn'], { sys_scope: scopes });
assert.equal(result.text, '\nApplication: sn_sec_cmn | Scope sys_id: scope-a | Records scanned: 0\nNo findings.');
result = run(['sn_sec_cmn'], { sys_scope: scopes }, ['sys_script'], { sys_ui_action: ['sys_scope'] });
assert.match(result.text, /Skipped tables:/);
assert.match(result.text, /No findings in completed checks/);
assert.ok(!result.queries.some(q => q.table === 'sys_script' || q.table === 'sys_ui_action'));
result = run(['sn_sec_cmn', 'sn_vul'], { sys_scope: [...scopes, { sys_id: 'duplicate', scope: 'sn_sec_cmn' }] });
assert.match(result.text, /Application skipped: sn_sec_cmn/);
assert.match(result.text, /Application: sn_vul/);
assert.ok(!result.queries.some(q => tables.includes(q.table) && q.filters.some(([, v]) => v === 'scope-a')));
result = run(['', ' ']);
assert.match(result.text, /No applications scanned/);
result = run(['sn_vul'], { ...data, sysauto_script: [record('job-b', 'scope-b', '', { active: '1' })] });
assert.match(result.text, /Warnings:/);
assert.match(result.text, /Active scheduled job has no Run as user/);
// Original behavior remains covered above. Customer/OOB selection cases follow.

const selectionData = {
    sys_scope: scopes,
    sys_script_include: [
        record('changed-oob', 'scope-a', 'gs.info("changed");'),
        record('new-custom', 'scope-a', 'gs.info("new");', { sys_mod_count: '0', sys_created_by: 'admin' }),
        record('updated-custom', 'scope-a', 'gs.info("update");'),
        record('marker-only', 'scope-a', 'gs.info("marked");', { sys_customer_update: 'true' }),
        record('marker-one', 'scope-a', 'gs.info("marked");', { sys_customer_update: '1' }),
        record('untouched-oob', 'scope-a', 'gs.info("stock");', { sys_customer_update: 'false', sys_mod_count: '99', sys_created_by: 'developer' }),
        record('bare-id', 'scope-a', 'gs.info("wrong key");'),
        record('wrong-table', 'scope-a', 'gs.info("wrong table");'),
        record('internal-only', 'scope-a', 'gs.info("internal");'),
        record('preview-only', 'scope-a', 'gs.info("not committed");'),
        record('delete-only', 'scope-a', 'gs.info("deleted");'),
        record('latest-delete', 'scope-a', 'gs.info("old customization");'),
        record('orphan-update', 'scope-a', 'gs.info("orphan");'),
        record('promoted-custom', 'scope-a', 'gs.info("committed");'),
        record('explicit-name', 'scope-a', 'gs.info("update name");', { sys_update_name: 'sys_script_include_real-update-name' }),
        record('subclass', 'scope-a', 'gs.info("subclass");', { sys_class_name: 'custom_script_include' }),
        record('outside', 'scope-b', 'gs.info("outside");', { sys_customer_update: 'true' })
    ],
    sys_update_xml: [
        update('sys_script_include_changed-oob'),
        update('sys_script_include_new-custom', { action: 'INSERT' }),
        update('sys_script_include_updated-custom', { action: 'UPDATE' }),
        update('bare-id'),
        update('sys_script_wrong-table'),
        update('sys_script_include_internal-only', { category: 'internal' }),
        update('sys_script_include_preview-only', { remote_update_set: 'retrieved', update_set: '' }),
        update('sys_script_include_delete-only', { action: 'DELETE' }),
        update('sys_script_include_latest-delete'),
        update('sys_script_include_latest-delete', { action: 'DELETE', sys_updated_on: '2026-09-24 11:00:00' }),
        update('sys_script_include_orphan-update', { update_set: '' }),
        update('sys_script_include_promoted-custom', { remote_update_set: 'committed-remote', update_set: '' }),
        update('sys_script_include_promoted-custom', { update_set: 'local-committed-copy' }),
        update('sys_script_include_real-update-name'),
        update('custom_script_include_subclass')
    ],
    // A baseline, plugin version, or old customer version does not qualify a record.
    sys_update_version: [
        { name: 'untouched-oob', state: 'CURRENT' },
        { name: 'sys_script_include_untouched-oob', state: 'CURRENT', source: 'System Upgrade' },
        { name: 'sys_script_include_untouched-oob', state: 'PREVIOUS', source: 'Update Set' },
        { name: 'sys_script_include_changed-oob', state: 'HISTORY', source_table: 'sys_upgrade_history' }
    ]
};
result = run(['sn_sec_cmn'], selectionData);
for (const id of ['changed-oob', 'new-custom', 'updated-custom', 'marker-only', 'marker-one', 'promoted-custom', 'explicit-name', 'subclass']) {
    assert.ok(result.text.includes(' | record: ' + id + ' |'), 'Expected included record: ' + id);
}
for (const id of ['untouched-oob', 'bare-id', 'wrong-table', 'internal-only', 'preview-only', 'delete-only', 'latest-delete', 'orphan-update', 'outside']) {
    assert.ok(!result.text.includes(' | record: ' + id + ' |'), 'Expected excluded record: ' + id);
}
assert.match(result.text, /Records scanned: 8/);
assert.ok(result.queries.filter(q => q.table === 'sys_update_version').every(q => !q.filters.some(([k, v]) => k === 'name' && v === 'sys_script_include_untouched-oob')));
// Missing virtual metadata fields still permit the exact table + sys_id lookup.
result = run(['sn_sec_cmn'], selectionData, [], { sys_script_include: ['sys_customer_update', 'sys_update_name', 'sys_class_name'] });
assert.match(result.text, /record: new-custom/);
assert.doesNotMatch(result.text, /record: untouched-oob/);
// Stop if required selection metadata is unavailable, never broaden the scan.
for (const field of ['name', 'category', 'action', 'update_set', 'remote_update_set']) {
    result = run(['sn_sec_cmn'], selectionData, [], { sys_update_xml: [field] });
    assert.match(result.text, /Scan stopped:/);
    assert.doesNotMatch(result.text, /No findings/);
    assert.equal(result.queries.length, 0);
}
result = run(['sn_sec_cmn'], selectionData, ['sys_update_xml']);
assert.match(result.text, /Scan stopped:/);
assert.equal(result.queries.length, 0);

// Every finding carries its origin, within an application block with the scope ID.
const reportData = {
    ...data,
    sys_update_version: [
        { name: 'sys_script_rule-a', source_table: 'sys_upgrade_history' },
        { name: 'sys_script_include_include-b', source_table: 'sys_store_app' }
    ],
    sys_update_xml: [...data.sys_update_xml, update('sys_script_rule-b', { action: 'INSERT' })]
};
result = run(['sn_sec_cmn', 'sn_vul'], reportData);
const appAHeader = 'Application: sn_sec_cmn | Scope sys_id: scope-a';
const appBHeader = 'Application: sn_vul | Scope sys_id: scope-b';
assert.ok(result.text.includes(appAHeader));
assert.ok(result.text.includes(appBHeader));
const splitAt = result.text.indexOf(appBHeader);
assert.ok(result.text.slice(0, splitAt).includes('record: rule-a'));
assert.ok(!result.text.slice(0, splitAt).includes('record: rule-b'));
assert.ok(result.text.slice(splitAt).includes('record: rule-b'));
assert.ok(!result.text.slice(splitAt).includes('record: rule-a'));
assert.match(result.text, /record: rule-a \| origin: Customized OOB\/Store file/);
assert.match(result.text, /record: include-b \| origin: Customized OOB\/Store file/);
assert.match(result.text, /record: rule-b \| origin: Custom Created/);
assert.match(result.text, /record: job-b \| origin: Custom Created/);
assert.ok(result.text.split('\n').filter(line => line.includes(' | record: ')).every(line => line.includes(' | origin: ')));
// Positive baseline evidence wins even if there is also an INSERT customer update.
result = run(['sn_sec_cmn'], {
    ...selectionData,
    sys_update_version: [...selectionData.sys_update_version, { name: 'sys_script_include_new-custom', source_table: 'sys_store_app' }]
});
assert.match(result.text, /record: new-custom \| origin: Customized OOB\/Store file/);
// Reporting policy maps unresolved customer-changed records to Custom Created.
result = run(['sn_sec_cmn'], selectionData);
assert.match(result.text, /record: marker-only \| origin: Custom Created/);
assert.match(result.text, /record: updated-custom \| origin: Custom Created/);
assert.match(result.text, /record: new-custom \| origin: Custom Created/);
for (const missingFields of [{ sys_update_version: ['source_table'] }, { sys_update_version: ['name'] }]) {
    result = run(['sn_sec_cmn'], selectionData, [], missingFields);
    assert.match(result.text, /record: changed-oob \| origin: Custom Created/);
    assert.ok(!result.queries.some(q => q.table === 'sys_update_version'));
}
result = run(['sn_sec_cmn'], selectionData, ['sys_update_version']);
assert.match(result.text, /record: new-custom \| origin: Custom Created/);
result = run(['sn_sec_cmn'], selectionData, [], {}, ['sys_update_version']);
assert.match(result.text, /record: new-custom \| origin: Custom Created/);
// Scheduled-job warnings retain record identity and origin too.
result = run(['sn_vul'], { ...reportData, sysauto_script: [record('job-b', 'scope-b', '', { active: '1' })] });
assert.match(result.text, /record: job-b \| origin: Custom Created.*Active scheduled job has no Run as user/);


// Exact names only, with priority based on custom-created vs delivered-file reporting origin.
const grData = {
    sys_scope: scopes,
    sys_script_include: [
        record('created-gr', 'scope-a', 'var gr; let GR; const Gr = 1; var gR = 2;', { sys_customer_update: 'true' }),
        record('descriptive-names', 'scope-a', 'var grMembers; let GRMembers; const gr_task = 1; var gr1; var gr$; var grπ;', { sys_customer_update: 'true' }),
        record('modified-oob-gr', 'scope-a', 'var gr;', { sys_customer_update: 'true' }),
        record('untouched-oob-gr', 'scope-a', 'var gr; gs.info("stock"); var id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'),
        record('untouched-no-baseline', 'scope-a', 'var GR;'),
        record('unknown-custom-gr', 'scope-a', 'var gr;'),
        record('outside-scope-gr', 'scope-b', 'var gr;', { sys_customer_update: 'true' })
    ],
    sys_script: [record('oob-rule-gr', 'scope-a', 'var gr; current.update(); gs.info("stock");')],
    sysauto_script: [record('oob-job-gr', 'scope-a', 'var gr;', { active: '1', run_as: 'inactive' })],
    sys_user: [{ sys_id: 'inactive', active: '0' }],
    sys_update_xml: [update('sys_script_include_unknown-custom-gr')],
    sys_update_version: [
        { name: 'sys_script_include_modified-oob-gr', source_table: 'sys_store_app' },
        { name: 'sys_script_include_untouched-oob-gr', source_table: 'sys_upgrade_history' }
    ]
};
result = run(['sn_sec_cmn'], grData);
assert.match(result.text, /record: created-gr \| origin: Custom Created \| priority: High \| exact-gr declarations: 4/);
assert.match(result.text, /record: unknown-custom-gr \| origin: Custom Created \| priority: High/);
assert.match(result.text, /record: modified-oob-gr \| origin: Customized OOB\/Store file \| priority: Low/);
assert.doesNotMatch(result.text, /record: untouched-oob-gr/);
assert.doesNotMatch(result.text, /record: untouched-no-baseline/);
assert.doesNotMatch(result.text, /record: oob-rule-gr/);
assert.doesNotMatch(result.text, /record: oob-job-gr/);
assert.doesNotMatch(result.text, /descriptive-names|outside-scope-gr|Unknown origin|origin review needed|Likely customer-created/);
// Untouched OOB records must not produce findings or scheduled-job warnings.
assert.doesNotMatch(result.text, /Hard-coded sys_ids|gs.info\(\)|current.update\(\)|Inactive Run as users|Warnings:/);
assert.ok(!result.queries.some(q => q.table === 'sys_user'));
assert.match(result.text, /sys_script_include \| Exact "gr" declarations: 6/);
assert.match(result.text, /Records scanned: 4/);
// Descriptive names alone produce no table or finding section.
result = run(['sn_sec_cmn'], {
    sys_scope: scopes,
    sys_script_include: [grData.sys_script_include[1]]
});
assert.equal(result.text, '\nApplication: sn_sec_cmn | Scope sys_id: scope-a | Records scanned: 1\nNo findings.');
// Per-user origin fallback applies even if baseline metadata cannot be queried.
result = run(['sn_sec_cmn'], grData, [], {}, ['sys_update_version']);
assert.match(result.text, /record: modified-oob-gr \| origin: Custom Created \| priority: High/);
assert.doesNotMatch(result.text, /record: untouched-oob-gr/);
// Both applications stay separate after applying the uniform record filter.
result = run(['sn_sec_cmn', 'sn_vul'], grData);
assert.ok(result.text.indexOf('record: outside-scope-gr') > result.text.indexOf(appBHeader));

// All five checks obey the same inclusion and priority policy.
const allPatterns = 'var gr; gs.info("example"); current.update(); var id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";';
const priorityData = {
    sys_scope: scopes,
    sys_script: [
        record('created-rule', 'scope-a', allPatterns, { sys_customer_update: 'true' }),
        record('modified-rule', 'scope-a', allPatterns, { sys_customer_update: 'true' }),
        record('stock-rule', 'scope-a', allPatterns)
    ],
    sysauto_script: [
        record('created-job', 'scope-a', '', { active: '1', run_as: 'inactive', sys_customer_update: 'true' }),
        record('modified-job', 'scope-a', '', { active: '1', run_as: 'inactive', sys_customer_update: 'true' }),
        record('stock-job', 'scope-a', allPatterns, { active: '1', run_as: 'inactive' })
    ],
    sys_script_client: [record('stock-client', 'scope-a', allPatterns)],
    sys_ui_action: [record('stock-action', 'scope-a', allPatterns)],
    sys_script_include: [record('stock-include', 'scope-a', allPatterns)],
    sys_user: [{ sys_id: 'inactive', name: 'Inactive User', active: '0' }],
    sys_update_version: [
        { name: 'sys_script_modified-rule', source_table: 'sys_upgrade_history' },
        { name: 'sysauto_script_modified-job', source_table: 'sys_store_app' },
        { name: 'sys_script_stock-rule', source_table: 'sys_upgrade_history' },
        { name: 'sysauto_script_stock-job', source_table: 'sys_store_app' }
    ]
};
result = run(['sn_sec_cmn'], priorityData);
for (const id of ['created-rule', 'created-job', 'modified-rule', 'modified-job']) {
    const lines = result.text.split('\n').filter(line => line.includes(' | record: ' + id + ' |'));
    assert.equal(lines.length, id.endsWith('rule') ? 4 : 1, 'All finding types for ' + id);
    for (const line of lines) {
        assert.equal((line.match(/priority:/g) || []).length, 1);
        if (id.startsWith('created')) {
            assert.match(line, /origin: Custom Created \| priority: High/);
            assert.doesNotMatch(line, /inherited from OOB/);
        } else {
            assert.match(line, /origin: Customized OOB\/Store file \| priority: Low \| note: finding may be inherited from OOB/);
        }
    }
}
assert.doesNotMatch(result.text, /stock-rule|stock-job|stock-client|stock-action|stock-include|UPMC/);
assert.match(result.text, /Records scanned: 4/);
assert.ok(!result.queries.some(q => q.table === 'sys_update_version' && q.filters.some(([key, value]) => key === 'name' && value.includes('stock-'))));
// When only untouched OOB records are present, no tables/details are printed at all.
const stockOnly = { ...priorityData };
for (const table of tables) stockOnly[table] = (priorityData[table] || []).filter(row => row.sys_id.startsWith('stock-'));
result = run(['sn_sec_cmn'], stockOnly);
assert.equal(result.text, '\nApplication: sn_sec_cmn | Scope sys_id: scope-a | Records scanned: 0\nNo findings.');
assert.ok(!result.queries.some(q => q.table === 'sys_user' || q.table === 'sys_update_version'));
// Guidance appears beneath every finding, for all five checks and both origins.
result = run(['sn_sec_cmn'], priorityData);
const reportLines = result.text.split('\n');
const guidancePairs = [];
for (let i = 0; i < reportLines.length; i++) {
    if (!reportLines[i].includes(' | record: ')) continue;
    assert.match(reportLines[i + 1], /^    Why: .+\.$/);
    assert.match(reportLines[i + 2], /^    Suggested alternative: .+\.$/);
    assert.ok(!reportLines[i + 3] || !reportLines[i + 3].startsWith('    Suggested alternative:'));
    guidancePairs.push(reportLines[i + 1] + '\n' + reportLines[i + 2]);
}
assert.equal(guidancePairs.length, 10);
assert.equal(new Set(guidancePairs).size, 5);
assert.doesNotMatch(result.text, /priority: (?:SEVERE|HIGH|LOW)/);
assert.equal((result.text.match(/priority: High/g) || []).length, 5);
assert.equal((result.text.match(/priority: Low/g) || []).length, 5);
// Verify the guidance follows its check, rather than a shared or miswired note.
const sections = [
    ['Hard-coded sys_ids:', /Why: .*sys_ids/, /Suggested alternative: .*lookup/],
    ['gs.info():', /Why: .*production logs/, /Suggested alternative: .*gs.debug\(\)/],
    ['Exact "gr" declarations:', /Why: .*shared scope/, /Suggested alternative: .*grMembers/],
    ['current.update():', /Why: .*recursion/, /Suggested alternative: .*before Business Rule/],
    ['Inactive Run as users:', /Why: .*inactive Run as/, /Suggested alternative: .*approved active Run as/]
];
for (const [heading, why, alternative] of sections) {
    const start = reportLines.indexOf(heading);
    assert.ok(start >= 0);
    assert.match(reportLines[start + 2], why);
    assert.match(reportLines[start + 3], alternative);
}
// Editing only the configuration text must change every corresponding finding.
const editedSource = source.replace(
    "why: 'Hardcoded sys_ids couple code to specific records that may differ between instances or be replaced.'",
    "why: 'Edited team explanation.'"
).replace(
    "alternative: 'Use a configurable reference, a server-side system property, or a validated record lookup instead of embedding the sys_id.'",
    "alternative: 'Edited team alternative.'"
);
result = run(['sn_sec_cmn'], priorityData, [], {}, [], editedSource);
assert.equal((result.text.match(/Why: Edited team explanation\./g) || []).length, 2);
assert.equal((result.text.match(/Suggested alternative: Edited team alternative\./g) || []).length, 2);
// No empty sections or remediation text when there are no findings.
result = run(['sn_sec_cmn'], stockOnly);
assert.doesNotMatch(result.text, /Why:|Suggested alternative:/);
// Missing Run as users are warnings, not inactive-user findings with misleading advice.
result = run(['sn_sec_cmn'], {
    sys_scope: scopes,
    sysauto_script: [record('warning-only', 'scope-a', '', { sys_customer_update: 'true', active: '1' })]
});
assert.match(result.text, /Active scheduled job has no Run as user/);
assert.doesNotMatch(result.text, /Why:|Suggested alternative:/);
console.log('Passed: High/Low priorities, editable per-finding guidance for all five checks, correct guidance mapping, empty output, warning handling, and selection/multi-scope regressions.');
