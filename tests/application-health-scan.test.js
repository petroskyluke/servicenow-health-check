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
        setLimit(limit) { this.limit = limit; }
        query() {
            queries.push({ table: this.table, filters: this.filters });
            this.rows = (data[this.table] || []).filter(row => this.filters.every(([k, v]) => row[k] === v)).slice(0, this.limit);
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
const data = {
    sys_scope: scopes,
    sys_script: [record('rule-a', 'scope-a', 'gs.info("a"); current.update();'), record('rule-b', 'scope-b', 'gs.info("b"); gs.info("c");'), record('foreign', 'other', 'gs.info("outside");')],
    sys_script_client: [record('clean', 'scope-a', 'var value = 1;'), record('uncustomized', 'scope-a', 'gs.info("ignored");')],
    sys_script_include: [record('include-b', 'scope-b', 'var grTask; var id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";')],
    sysauto_script: [record('job-b', 'scope-b', '', { active: '1', run_as: 'inactive' })],
    sys_user: [{ sys_id: 'inactive', name: 'Inactive User', active: '0' }],
    sys_update_version: ['rule-a', 'rule-b', 'foreign', 'clean', 'include-b', 'job-b'].map(name => ({ name }))
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
console.log('Passed: scope lookup, multiple applications, isolation, duplicate/missing scopes, empty output, all finding types, customization filter, skipped tables, and warnings.');
