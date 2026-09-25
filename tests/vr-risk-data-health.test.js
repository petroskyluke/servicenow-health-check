const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../Scripts/ATF/VRRiskDataHealth.js'), 'utf8');

const vit = (score, rating, extra = {}) => ({ active: true, source: 'scanner-a', risk_score: score, risk_rating: rating, ...extra });
const healthy = [vit('95', '1'), vit('75', '2'), vit('50', '3'), vit('20', '4'), vit('0', '5')];
const checks = ['configuration', 'population', 'values', 'consistency', 'distribution'];
let tested = 0;

// Model stored records, filters and database grouping independently of the helper.
// These mocks exercise control flow; they do not replace validation in ServiceNow.
function setup(rows = healthy, options = {}) {
    const originalRows = JSON.stringify(rows);
    const queries = [];
    const writes = [];
    const fields = new Set(['active', 'source', 'risk_score', 'risk_rating', 'sys_created_on', 'sys_id']);
    const stringify = value => value === null || value === undefined ? '' : String(value);
    function matches(row, [field, operator, value]) {
        const stored = stringify(row[field]);
        const expected = stringify(value);
        if (operator === '=') return stored === expected;
        if (operator === '!=') return stored !== expected;
        if (operator === 'IN') return expected.split(',').includes(stored);
        if (operator === 'NOT IN') return !expected.split(',').includes(stored);
        if (operator === '>') return stored > expected;
        if (operator === '>=') return stored >= expected;
        if (operator === '<') return stored < expected;
        if (operator === '<=') return stored <= expected;
        throw new Error('Unexpected query operator: ' + operator);
    }
    class GlideRecord {
        constructor(table) { this.table = table; }
        isValid() { return this.table === 'sn_vul_vulnerable_item' && !options.invalidTable; }
        isValidField(field) { return fields.has(field) && !(options.missingFields || []).includes(field); }
    }
    class GlideAggregate extends GlideRecord {
        constructor(table) { super(table); this.filters = []; this.groups = []; this.index = -1; }
        addQuery(field, operator, value) {
            assert.ok(this.isValidField(field), 'Invalid field reached database: ' + field);
            this.filters.push([field, operator, value]);
        }
        addAggregate(aggregate, field) {
            assert.equal(aggregate, 'COUNT');
            assert.equal(field, undefined, 'COUNT(field) would discard null values');
        }
        groupBy(field) { assert.ok(this.isValidField(field)); this.groups.push(field); }
        setGroup(enabled) { assert.equal(enabled, false); this.groups = []; }
        query() {
            queries.push({ table: this.table, filters: this.filters.map(filter => [...filter]), groups: [...this.groups] });
            if (options.queryError && (!options.queryErrorGroupOnly || this.groups.length)) throw new Error('Query denied');
            const selected = rows.filter(row => this.filters.every(filter => matches(row, filter)));
            if (!this.groups.length) {
                this.results = [{ count: options.populationCount === undefined ? String(selected.length) : options.populationCount }];
                return;
            }
            const buckets = new Map();
            for (const row of selected) {
                if (options.omitNullGroups && this.groups.some(field => row[field] == null || row[field] === '')) continue;
                const key = JSON.stringify(this.groups.map(field => row[field] ?? null));
                if (!buckets.has(key)) buckets.set(key, { ...row, count: 0 });
                buckets.get(key).count++;
            }
            this.results = [...buckets.values()].map(row => ({ ...row, count: String(row.count) }));
            if (options.groupCount !== undefined && this.results.length) this.results[0].count = options.groupCount;
        }
        next() { return ++this.index < this.results.length; }
        getValue(field) { return this.results[this.index][field] ?? null; }
        getAggregate(aggregate) { assert.equal(aggregate, 'COUNT'); return this.results[this.index].count; }
    }
    for (const method of ['insert', 'update', 'updateMultiple', 'deleteRecord', 'deleteMultiple', 'setValue']) {
        GlideRecord.prototype[method] = function() { writes.push(method); throw new Error('Health checks must not mutate records'); };
    }
    const context = vm.createContext({
        GlideRecord,
        GlideAggregate,
        Class: { create: () => function() { this.initialize.apply(this, arguments); } }
    });
    vm.runInContext(source, context);
    const helper = new context.VRRiskDataHealth();
    if (!options.defaultConfig) {
        helper.config.configurationReviewed = true;
        helper.config.minimumRecords = 1;
        helper.config.ratings.forEach(rating => { rating.minPercent = 0; rating.maxPercent = 100; });
    }
    return {
        helper, queries,
        run(check) {
            const result = helper.run(check);
            assert.equal(typeof result.passed, 'boolean');
            assert.equal(typeof result.message, 'string');
            assert.deepEqual(writes, [], 'No mutation API may be attempted');
            assert.equal(JSON.stringify(rows), originalRows, 'Input records must remain unchanged');
            return result;
        }
    };
}

function test(name, callback) {
    try { callback(); tested++; }
    catch (error) { error.message = name + ': ' + error.message; throw error; }
}
function pass(result) { assert.equal(result.passed, true, result.message); }
function fail(result, message) {
    assert.equal(result.passed, false, result.message);
    if (message) assert.match(result.message, message);
}

test('all five checks accept configured healthy data', () => {
    const environment = setup();
    environment.helper.config.minimumRecords = healthy.length;
    environment.helper.config.ratings.forEach(rating => { rating.minPercent = 20; rating.maxPercent = 20; });
    for (const check of checks) pass(environment.run(check));
    const report = environment.run('distribution').message;
    assert.match(report, /VITs: 5/);
    for (const label of ['Critical', 'High', 'Medium', 'Low', 'None']) assert.ok(report.includes(label + ': 20.00%'));
    assert.match(report, /Mean score: 48.00 \(informational\)/);
});

test('default configuration cannot pass or query data', () => {
    const environment = setup(healthy, { defaultConfig: true });
    for (const check of checks) fail(environment.run(check), /configurationReviewed/);
    assert.equal(environment.queries.length, 0);
    environment.helper.config.configurationReviewed = true;
    fail(environment.run('configuration'), /minPercent and maxPercent/);
    assert.equal(environment.queries.length, 0);
});

test('invalid configuration and schema fail before database queries', () => {
    const mutations = [
        config => { config.table = 'unknown_table'; },
        config => { config.table = 'table.with_dot'; },
        config => { config.scoreField = 'not_a_field'; },
        config => { config.ratingField = 'risk_score'; },
        config => { config.filters = []; },
        config => { config.filters[0].field = 'bad_field'; },
        config => { config.filters[0].field = 'vulnerability.severity'; },
        config => { config.filters[0].field = 'risk_score'; },
        config => { config.filters[0].field = 'risk_rating'; },
        config => { config.filters[0].operator = 'UNKNOWN'; },
        config => { config.filters[0].value = ''; },
        config => { config.filters[0].value = null; },
        config => { config.filters[0].value = 'javascript:gs.now()'; },
        config => { config.filters[0].value = Infinity; },
        config => { config.minimumRecords = 0; },
        config => { config.minimumRecords = 1.5; },
        config => { config.populationLabel = ' '; },
        config => { config.ratings.pop(); },
        config => { config.ratings[0].value = config.ratings[1].value; },
        config => { config.ratings[0].minPercent = null; },
        config => { config.ratings[0].maxPercent = '20'; },
        config => { config.ratings[0].maxPercent = NaN; },
        config => { config.ratings[0].minPercent = 30; config.ratings[0].maxPercent = 20; },
        config => { config.ratings[0].maxPercent = 101; },
        config => { config.ratings[0].minPercent = -1; },
        config => { config.ratings.forEach(rating => { rating.minPercent = 21; }); },
        config => { config.ratings.forEach(rating => { rating.maxPercent = 19; }); },
        config => { config.ratings[0].scoreMin = 91; },
        config => { config.ratings[0].scoreMin = 89; },
        config => { config.ratings[0].scoreMax = 99; },
        config => { config.meanScore = { min: 20, max: null }; },
        config => { config.meanScore = { min: 20, max: 19 }; }
    ];
    for (const mutate of mutations) {
        const environment = setup();
        mutate(environment.helper.config);
        fail(environment.run('distribution'));
        assert.equal(environment.queries.length, 0, String(mutate));
    }
    for (const options of [{ invalidTable: true }, { missingFields: ['risk_score'] }, { missingFields: ['risk_rating'] }, { missingFields: ['active'] }]) {
        const environment = setup(healthy, options);
        fail(environment.run('configuration'));
        assert.equal(environment.queries.length, 0);
    }
});

test('empty and undersized populations fail, with the exact minimum passing', () => {
    for (const rows of [[], [healthy[0]]]) {
        const environment = setup(rows);
        environment.helper.config.minimumRecords = 2;
        for (const check of checks.slice(1)) fail(environment.run(check), /Insufficient data/);
    }
    const environment = setup(healthy.slice(0, 2));
    environment.helper.config.minimumRecords = 2;
    pass(environment.run('population'));
});

test('missing, malformed, fractional and out-of-range scores never pass downstream checks', () => {
    for (const score of [null, undefined, '', ' ', 'NaN', 'Infinity', '2.5', '-1', '101', '0x10', '1e1']) {
        const environment = setup([vit(score, '5')]);
        for (const check of ['values', 'consistency', 'distribution']) fail(environment.run(check), /Missing\/invalid scores: 1/);
    }
});

test('blank and unknown ratings are not treated as None', () => {
    for (const rating of [null, undefined, '', ' ', '0', '6', 'Critical']) {
        const environment = setup([vit('0', rating)]);
        for (const check of ['values', 'consistency', 'distribution']) fail(environment.run(check), /Missing\/invalid ratings: 1/);
    }
    pass(setup([vit('0', '5')]).run('values'));
});

test('score bands include every boundary and use stored rating values', () => {
    const rows = [[0, '5'], [1, '4'], [39, '4'], [40, '3'], [69, '3'], [70, '2'], [89, '2'], [90, '1'], [100, '1']].map(([score, rating]) => vit(String(score), rating));
    pass(setup(rows).run('consistency'));
    const environment = setup([vit('95', 'critical')]);
    environment.helper.config.ratings[0].value = 'critical';
    pass(environment.run('consistency'));
});

test('score/rating mismatch cannot pass distribution', () => {
    const environment = setup([vit('89', '1'), vit('0', '4')]);
    pass(environment.run('values'));
    fail(environment.run('consistency'), /mismatches: 2/);
    fail(environment.run('distribution'), /mismatches: 2/);
});

test('all-zero None data and absent expected categories are detected', () => {
    const environment = setup([vit('0', '5'), vit('0', '5')]);
    environment.helper.config.ratings[4].maxPercent = 10;
    fail(environment.run('distribution'), /None: 100\.0000% \(2\/2\); expected 0-10%/);
    const missing = setup([vit('20', '4')]);
    missing.helper.config.ratings[0].minPercent = 1;
    fail(missing.run('distribution'), /Critical: 0\.0000% \(0\/1\); expected 1-100%/);
});

test('percentage comparisons are inclusive and use unrounded values', () => {
    const environment = setup([vit('95', '1'), vit('0', '5'), vit('0', '5')]);
    environment.helper.config.ratings[0].maxPercent = 33.33;
    fail(environment.run('distribution'), /Critical: 33\.3333%/);
    environment.helper.config.ratings[0].minPercent = 100 / 3;
    environment.helper.config.ratings[0].maxPercent = 100 / 3;
    pass(environment.run('distribution'));
    environment.helper.config.ratings[0].minPercent = 33.334;
    environment.helper.config.ratings[0].maxPercent = 100;
    fail(environment.run('distribution'), /Critical: 33\.3333%/);
});

test('optional mean weights repeated scores by record count and honors inclusive bounds', () => {
    const environment = setup([vit('100', '1'), ...Array.from({ length: 9 }, () => vit('0', '5'))]);
    environment.helper.config.meanScore = { min: 10, max: 10 };
    const result = environment.run('distribution');
    pass(result);
    assert.match(result.message, /Mean score: 10\.00$/);
    environment.helper.config.meanScore = { min: 10.01, max: 100 };
    fail(environment.run('distribution'), /Mean score: 10\.0000; expected 10.01-100/);
    environment.helper.config.meanScore = { min: 0, max: 9.99 };
    fail(environment.run('distribution'), /Mean score: 10\.0000; expected 0-9.99/);
});

test('database failures cannot produce a green result', () => {
    for (const options of [{ queryError: true }, { queryError: true, queryErrorGroupOnly: true }]) {
        const environment = setup(healthy, options);
        fail(environment.run('distribution'), /Query denied/);
    }
    for (const options of [{ populationCount: 'NaN' }, { populationCount: '-1' }, { groupCount: '0' }, { groupCount: 'NaN' }, { groupCount: '1.5' }]) {
        fail(setup(healthy, options).run('distribution'), /count|aggregate/i);
    }
});

test('ungrouped count detects omitted null groups and population changes', () => {
    const cases = [
        { rows: [...healthy, vit(null, '5')], options: { omitNullGroups: true } },
        { rows: [...healthy, vit('0', null)], options: { omitNullGroups: true } },
        { rows: healthy, options: { populationCount: '6' } },
        { rows: healthy, options: { populationCount: '4' } }
    ];
    for (const { rows, options } of cases) {
        const environment = setup(rows, options);
        fail(environment.run('distribution'), /count|population|group|changed|reconcil/i);
        assert.ok(environment.queries.some(query => query.groups.length === 0), 'An independent total is required');
        assert.ok(environment.queries.some(query => query.groups.length === 2), 'Scores and ratings must both be grouped');
    }
});

test('all aggregate queries use the same validated AND population filters', () => {
    const rows = [
        ...healthy,
        vit(null, null, { active: false }),
        vit(null, null, { source: 'scanner-b' })
    ];
    const environment = setup(rows);
    environment.helper.config.filters.push({ field: 'source', operator: '=', value: 'scanner-a' });
    const result = environment.run('distribution');
    pass(result);
    assert.match(result.message, /VITs: 5/);
    assert.ok(environment.queries.length >= 2);
    for (const query of environment.queries) {
        assert.equal(query.table, 'sn_vul_vulnerable_item');
        assert.deepEqual(query.filters, [['active', '=', true], ['source', '=', 'scanner-a']]);
    }
    environment.helper.config.filters[1] = { field: 'source', operator: 'IN', value: 'scanner-a,scanner-c' };
    pass(environment.run('distribution'));
});

test('unknown checks fail without querying or mutating records', () => {
    const environment = setup();
    fail(environment.run('not-a-check'), /Unknown check/);
    assert.equal(environment.queries.length, 0);
});

console.log('Passed: ' + tested + ' VR risk health scenarios, including configuration, five ATF checks, null handling, thresholds, weighted mean, count reconciliation, filters and read-only behavior.');
