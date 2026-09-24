const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../Scripts/USEM_HC_ApplicationHealthScan.js'), 'utf8');
const tables = ['sys_script_client', 'sys_script', 'sys_ui_action', 'sys_script_include', 'sysauto_script'];

function run(apps, data = {}, invalid = [], missingFields = {}) {
    const output = [], queries = [];
    class GlideRecord {
        constructor(table) { this.table = table; this.filters = []; this.rows = []; this.index = -1; this.limit = Infinity; }
        addQuery(field, value) { this.filters.push([field, value]); }
        addNotNullQuery(field) { this.filters.push([field, 'NOT_NULL']); }
        addNullQuery(field) { this.filters.push([field, 'NULL']); }
        orderByDesc(field) { this.sortField = field; }
        setLimit(limit) { this.limit = limit; }
        query() {
            queries.push({ table: this.table, filters: this.filters });
            for (const [field] of this.filters) assert.ok(this.isValidField(field), 'Invalid query field: ' + field);
            this.rows = (data[this.table] || []).filter(row => this.filters.every(([k, v]) => {
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
    vm.runInNewContext(source.replace("var appNames = ['sn_sec_cmn'];", 'var appNames = ' + JSON.stringify(apps) + ';'), {
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
    sys_script_include: [record('include-b', 'scope-b', 'var grTask; var id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";')],
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
assert.match(result.text, /hard-coded sys_ids: 1 \| "gr" declarations: 1/);
assert.match(result.text, /inactive Run as users: 1/);
assert.doesNotMatch(result.text, /foreign|uncustomized|sys_script_client|sys_ui_action|OVERALL SUMMARY/);
assert.ok(result.queries.filter(q => q.table === 'sys_scope').every(q => q.filters[0][0] === 'scope'));
assert.ok(result.queries.filter(q => tables.includes(q.table)).every(q => q.filters.some(([k, v]) => k === 'sys_scope' && ['scope-a', 'scope-b'].includes(v))));
result = run(['sn_sec_cmn'], { sys_scope: scopes });
assert.equal(result.text, 'Application: sn_sec_cmn | Records scanned: 0\nNo findings.');
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
        { name: 'sys_script_include_changed-oob', state: 'HISTORY', source: 'System Upgrade' }
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
assert.ok(!result.queries.some(q => q.table === 'sys_update_version'));
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
console.log('Passed: scope selection, multiple apps, all finding types, concise output, custom inserts, customized OOB, untouched OOB exclusion, exact update names, applied updates, deletion filtering, and unavailable metadata.');
