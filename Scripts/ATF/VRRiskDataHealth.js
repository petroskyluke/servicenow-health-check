/*
 * Vulnerability Response (sn_vul), server-only Script Include: VRRiskDataHealth
 * One ATF test uses this helper from the five scripts in steps/.
 * Reads existing VITs only; never updates records or recalculates risk.
 * Setup and sources: README.md in this directory.
 */
var VRRiskDataHealth = Class.create();
VRRiskDataHealth.prototype = {
    initialize: function() {
        /**************************************************************
         * ALL TEST SETTINGS - EDIT ONLY THIS CONFIGURATION BLOCK.
         * Shared by all five steps; no settings need editing in the steps.
         * Percentage ranges below are illustrative samples, not measured baselines.
         * Use a verified healthy population to decide acceptable ranges.
         **************************************************************/
        this.config = {
            // 1. CONFIGURATION REVIEW
            configurationReviewed: false, // Set true after reviewing ALL settings.

            // 2. TABLE, FIELDS AND POPULATION
            table: 'sn_vul_vulnerable_item',
            scoreField: 'risk_score',
            ratingField: 'risk_rating',
            populationLabel: 'Active VITs',
            // Direct fields only; all conditions are ANDed. Use stored values.
            filters: [
                { field: 'active', operator: '=', value: true }
                // Example: { field: 'source', operator: '=', value: 'YOUR_SOURCE' }
            ],
            minimumRecords: 40000000,
            maximumRecords: 100000000,

            // 3. COUNT VARIANCE BETWEEN THE TWO QUERIES
            // Percentage of populationCount; 0 requires an exact match.
            // 0.0125% = 5,000 records at 40 million; 12,500 at 100 million.
            // Fractional allowed counts round DOWN.
            populationCountTolerance: {
                maxDifferencePercent: 0.0125
            },

            // 4. SCORE DOMAIN, RATING MAPPING AND ACCEPTED PERCENTAGES
            // Integer score domain and rating bands must match YOUR instance.
            scoreMinimum: 0,
            scoreMaximum: 100,
            ratings: [
                { value: '1', label: 'Critical', scoreMin: 90, scoreMax: 100, minPercent: 0.1, maxPercent: 1.5 },
                { value: '2', label: 'High',     scoreMin: 70, scoreMax: 89,  minPercent: 0.5, maxPercent: 5 },
                { value: '3', label: 'Medium',   scoreMin: 40, scoreMax: 69,  minPercent: 10, maxPercent: 30 },
                { value: '4', label: 'Low',      scoreMin: 1,  scoreMax: 39,  minPercent: 55, maxPercent: 85 },
                { value: '5', label: 'None',     scoreMin: 0,  scoreMax: 0,   minPercent: 0, maxPercent: 10 }
            ],
            // 5. SCORE/RATING MISMATCH ALLOWANCE BY INSTANCE
            // Exact instance_name property values, ignoring case/outer whitespace.
            // Replace DEV/ENG/TEST with your actual instance names if different.
            // Only Dev and Eng can have an allowance; Test and all others stay at 0.
            // Percentage of grouped VITs; fractional allowed counts round DOWN.
            // 0.00002% allows 8 mismatches at 40 million, 20 at 100 million.
            mismatchTolerance: {
                dev: { instanceName: 'DEV', maxPercent: 0.00002 },
                eng: { instanceName: 'ENG', maxPercent: 0.00002 },
                test: { instanceName: 'TEST' }
            },

            // 6. OPTIONAL MEAN-SCORE BOUNDS
            // Helps catch lower scores even within the same rating.
            // Both null disables this extra check; otherwise set BOTH bounds.
            meanScore: { min: null, max: null },

            // 7. REPORT DISPLAY (comparisons always use full precision)
            outputDecimals: 6
        };
        /**************** END OF ALL EDITABLE TEST SETTINGS ****************/
    },

    run: function(check) {
        try {
            if (['configuration', 'population', 'values', 'consistency', 'distribution'].indexOf(check) < 0)
                throw new Error('Unknown check: ' + check);
            this._validateConfiguration();
            if (check === 'configuration')
                return { passed: true, message: 'Pass | Configuration and fields validated.' };

            var snapshot = this._readSnapshot();
            var prefix = this.config.populationLabel + ' | VITs: ' + snapshot.total;
            if (snapshot.countDifference)
                prefix += ' | Count variance: ' + snapshot.countDifference + ' (population: ' + snapshot.populationCount + '; allowed: ' + snapshot.allowedCountDifference + ')';
            var failures = this._populationFailures(snapshot);
            if (check === 'population') return this._result(prefix, failures);

            if (snapshot.invalidScores) failures.push('Missing/invalid scores: ' + snapshot.invalidScores);
            if (snapshot.invalidRatings) failures.push('Missing/invalid ratings: ' + snapshot.invalidRatings);
            if (check === 'values') return this._result(prefix, failures);
            var mismatch = this._mismatchStatus(snapshot);
            if (!mismatch.passed) failures.push(mismatch.message);
            if (check === 'consistency') return this._result(prefix, failures, mismatch.passed ? [mismatch.message] : []);

            // Step 5 always includes ALL five categories, even with prerequisite failures.
            var rows = mismatch.passed ? [mismatch.message] : [];
            for (var i = 0; i < this.config.ratings.length; i++) {
                var rating = this.config.ratings[i];
                if (!snapshot.total) {
                    rows.push(rating.label + ': unavailable | expected: ' + rating.minPercent + '-' + rating.maxPercent + '% | Fail | no grouped records');
                    continue;
                }
                var percent = 100 * snapshot.ratingCounts[i] / snapshot.total;
                var status = this._rangeStatus(percent, rating.minPercent, rating.maxPercent, 'percentage points');
                rows.push(rating.label + ': ' + this._display(percent) + '% | expected: ' + rating.minPercent + '-' + rating.maxPercent +
                    '% | ' + (status.passed ? 'Pass' : 'Fail') + ' | ' + status.detail + ' | count: ' + snapshot.ratingCounts[i] + '/' + snapshot.total);
                if (!status.passed) failures.push(rating.label + ' outside expected range');
            }
            if (snapshot.total && !snapshot.invalidScores) {
                var mean = snapshot.scoreSum / snapshot.total;
                var bounds = this.config.meanScore;
                if (bounds.min === null) rows.push('Mean score: ' + this._display(mean) + ' (informational)');
                else {
                    var meanStatus = this._rangeStatus(mean, bounds.min, bounds.max, 'score points');
                    rows.push('Mean score: ' + this._display(mean) + ' | expected: ' + bounds.min + '-' + bounds.max +
                        ' | ' + (meanStatus.passed ? 'Pass' : 'Fail') + ' | ' + meanStatus.detail);
                    if (!meanStatus.passed) failures.push('Mean score outside expected range');
                }
            } else rows.push('Mean score: unavailable | Fail | missing/invalid scores or empty data');
            return this._result(prefix, failures, rows);
        } catch (error) {
            var message = 'Fail | ' + String(error.message || error);
            if (check === 'distribution') {
                var labels = ['Critical', 'High', 'Medium', 'Low', 'None'];
                for (var i = 0; i < labels.length; i++) {
                    var rating = this.config && this.config.ratings && this.config.ratings[i];
                    var expected = rating ? rating.minPercent + '-' + rating.maxPercent + '%' : 'unavailable';
                    message += '\n' + labels[i] + ': unavailable | expected: ' + expected + ' | Fail | check could not complete';
                }
            }
            return { passed: false, message: message };
        }
    },

    _instanceName: function(value) {
        return String(value || '').replace(/^\s+|\s+$/g, '').toLowerCase();
    },
    _mismatchStatus: function(snapshot) {
        var instance = this._instanceName(gs.getProperty('instance_name', ''));
        var settings = this.config.mismatchTolerance;
        var environment = 'Unmatched instance';
        var percent = 0;
        if (instance === this._instanceName(settings.dev.instanceName)) {
            environment = 'Dev';
            percent = settings.dev.maxPercent;
        } else if (instance === this._instanceName(settings.eng.instanceName)) {
            environment = 'Eng';
            percent = settings.eng.maxPercent;
        } else if (instance === this._instanceName(settings.test.instanceName)) environment = 'Test';
        var allowed = Math.floor(snapshot.total * percent / 100);
        var passed = snapshot.mismatches <= allowed;
        return { passed: passed, message: 'Score/rating mismatches: ' + snapshot.mismatches +
            ' actual | allowed: ' + allowed + ' (' + percent + '% of ' + snapshot.total +
            ' grouped VITs) | Environment: ' + environment + ' | ' + (passed ? 'Pass' : 'Fail') +
            (passed ? ' | within allowance' : ' | above allowance by ' + (snapshot.mismatches - allowed) + ' records') };
    },
    _validateMismatchTolerance: function() {
        var settings = this.config.mismatchTolerance;
        if (!settings) throw new Error('Configure mismatchTolerance for Dev, Eng and Test.');
        var keys = ['dev', 'eng', 'test'];
        var seen = {};
        for (var i = 0; i < keys.length; i++) {
            var entry = settings[keys[i]];
            if (!entry || typeof entry.instanceName !== 'string' || !this._instanceName(entry.instanceName))
                throw new Error('mismatchTolerance.' + keys[i] + '.instanceName must be a nonempty string.');
            var name = this._instanceName(entry.instanceName);
            if (seen['name:' + name]) throw new Error('Mismatch tolerance instance names must be distinct.');
            seen['name:' + name] = true;
            if (keys[i] !== 'test' && (typeof entry.maxPercent !== 'number' || !isFinite(entry.maxPercent) ||
                entry.maxPercent < 0 || entry.maxPercent > 100))
                throw new Error('mismatchTolerance.' + keys[i] + '.maxPercent must be a number from 0 through 100.');
        }
    },
    _populationFailures: function(snapshot) {
        var failures = [];
        if (snapshot.countDifference > snapshot.allowedCountDifference)
            failures.push('Population count variance exceeds tolerance; population: ' + snapshot.populationCount + ', grouped: ' + snapshot.total +
                ', difference: ' + snapshot.countDifference + ', allowed: ' + snapshot.allowedCountDifference +
                ' (' + this.config.populationCountTolerance.maxDifferencePercent + '%); above allowance by ' +
                (snapshot.countDifference - snapshot.allowedCountDifference) + ' records');
        var counts = [{ label: 'Population', value: snapshot.populationCount }, { label: 'Grouped', value: snapshot.total }];
        for (var i = 0; i < counts.length; i++) {
            var count = counts[i];
            if (count.value < this.config.minimumRecords)
                failures.push('Insufficient data | ' + count.label + ': ' + count.value + ' | minimum: ' + this.config.minimumRecords +
                    ' | below min by ' + (this.config.minimumRecords - count.value) + ' records');
            if (count.value > this.config.maximumRecords)
                failures.push('Population too large | ' + count.label + ': ' + count.value + ' | maximum: ' + this.config.maximumRecords +
                    ' | above max by ' + (count.value - this.config.maximumRecords) + ' records');
        }
        return failures;
    },
    _rangeStatus: function(value, min, max, units) {
        // Percentage differences are percentage POINTS, not relative percent changes.
        if (value < min) return { passed: false, detail: 'below min by ' + this._delta(min - value) + ' ' + units };
        if (value > max) return { passed: false, detail: 'above max by ' + this._delta(value - max) + ' ' + units };
        return { passed: true, detail: 'within range' };
    },
    _display: function(value) { return value.toFixed(this.config.outputDecimals); },
    _delta: function(value) {
        var displayed = this._display(value);
        return Number(displayed) === 0 && value > 0 ? '<' + this._display(Math.pow(10, -this.config.outputDecimals)) : displayed;
    },
    _result: function(prefix, failures, rows) {
        return { passed: failures.length === 0, message: (failures.length ? 'Fail' : 'Pass') + ' | ' + prefix +
            (failures.length ? '\n' + failures.join('\n') : '') + (rows && rows.length ? '\n' + rows.join('\n') : '') };
    },

    _validateConfiguration: function() {
        var config = this.config;
        if (config.configurationReviewed !== true)
            throw new Error('Review ALL TEST SETTINGS in initialize, including count tolerance; then set configurationReviewed to true.');
        this._validateMismatchTolerance();
        if (!this._integer(config.minimumRecords) || config.minimumRecords < 1)
            throw new Error('minimumRecords must be a positive integer.');
        if (!this._integer(config.maximumRecords) || config.maximumRecords < config.minimumRecords)
            throw new Error('maximumRecords must be an integer greater than or equal to minimumRecords.');
        if (!this._integer(config.outputDecimals) || config.outputDecimals < 0 || config.outputDecimals > 10)
            throw new Error('outputDecimals must be an integer from 0 through 10.');
        var tolerance = config.populationCountTolerance;
        if (!tolerance || typeof tolerance.maxDifferencePercent !== 'number' || !isFinite(tolerance.maxDifferencePercent) ||
            tolerance.maxDifferencePercent < 0 || tolerance.maxDifferencePercent > 100)
            throw new Error('populationCountTolerance.maxDifferencePercent must be a number from 0 through 100.');
        if (!this._integer(config.scoreMinimum) || !this._integer(config.scoreMaximum) || config.scoreMinimum < 0 || config.scoreMinimum >= config.scoreMaximum)
            throw new Error('Score domain must have nonnegative integer bounds with minimum < maximum.');
        if (typeof config.populationLabel !== 'string' || !config.populationLabel.replace(/\s/g, ''))
            throw new Error('Set a descriptive populationLabel.');
        if (!/^[a-zA-Z0-9_]+$/.test(config.table)) throw new Error('Invalid table name.');
        var record = new GlideRecord(config.table);
        if (!record.isValid()) throw new Error('Table unavailable: ' + config.table);
        this._validateField(record, config.scoreField);
        this._validateField(record, config.ratingField);
        if (config.scoreField === config.ratingField) throw new Error('Score and rating must use different fields.');
        if (!this._array(config.filters) || !config.filters.length)
            throw new Error('Define at least one population filter.');
        for (var i = 0; i < config.filters.length; i++) {
            var filter = config.filters[i];
            this._validateField(record, filter.field);
            // Filtering on these fields could hide exactly the bad data being tested.
            if (filter.field === config.scoreField || filter.field === config.ratingField)
                throw new Error('Population filters must not exclude scores or ratings.');
            if (['=', '!=', 'IN', 'NOT IN', '>', '>=', '<', '<='].indexOf(filter.operator) < 0)
                throw new Error('Unsupported filter operator: ' + filter.operator);
            if (filter.value === null || typeof filter.value === 'undefined' ||
                ['string', 'number', 'boolean'].indexOf(typeof filter.value) < 0 ||
                (typeof filter.value === 'number' && !isFinite(filter.value)) ||
                (typeof filter.value === 'string' && (!filter.value.replace(/\s/g, '') || /^javascript:/i.test(filter.value))))
                throw new Error('Use a literal, nonempty filter value for ' + filter.field + '.');
        }
        var labels = ['Critical', 'High', 'Medium', 'Low', 'None'];
        if (!this._array(config.ratings) || config.ratings.length !== 5)
            throw new Error('Configure all five risk ratings.');
        var seenValues = {};
        var sumMin = 0;
        var sumMax = 0;
        var orderedBands = [];
        var unset = [];
        for (i = 0; i < config.ratings.length; i++) {
            var rating = config.ratings[i];
            if (rating.label !== labels[i]) throw new Error('Keep rating labels in Critical, High, Medium, Low, None order.');
            if (typeof rating.value !== 'string' || !rating.value.replace(/\s/g, '') || seenValues['v:' + rating.value])
                throw new Error('Rating values must be unique nonempty strings.');
            seenValues['v:' + rating.value] = true;
            if (!this._integer(rating.scoreMin) || !this._integer(rating.scoreMax) || rating.scoreMin > rating.scoreMax ||
                rating.scoreMin < config.scoreMinimum || rating.scoreMax > config.scoreMaximum)
                throw new Error('Invalid score band: ' + rating.label);
            orderedBands.push(rating);
            if (rating.minPercent === null || rating.maxPercent === null) {
                unset.push(rating.label);
            } else {
                this._validateRange(rating.minPercent, rating.maxPercent, 0, 100, rating.label + ' percentages');
                sumMin += rating.minPercent;
                sumMax += rating.maxPercent;
            }
        }
        if (unset.length) throw new Error('Set minPercent and maxPercent for: ' + unset.join(', ') + '.');
        if (sumMin > 100 || sumMax < 100)
            throw new Error('Percentage ranges cannot sum to 100%: sum(min) must be <= 100 and sum(max) >= 100.');
        orderedBands.sort(function(a, b) { return a.scoreMin - b.scoreMin; });
        var nextScore = config.scoreMinimum;
        for (i = 0; i < orderedBands.length; i++) {
            if (orderedBands[i].scoreMin !== nextScore) throw new Error('Score bands must cover the score domain without gaps or overlaps.');
            nextScore = orderedBands[i].scoreMax + 1;
        }
        if (nextScore !== config.scoreMaximum + 1) throw new Error('Score bands must cover the entire score domain.');
        if (!config.meanScore) throw new Error('Configure meanScore or set both bounds to null.');
        if (config.meanScore.min !== null || config.meanScore.max !== null)
            this._validateRange(config.meanScore.min, config.meanScore.max, config.scoreMinimum, config.scoreMaximum, 'Mean score');
    },

    _readSnapshot: function() {
        var config = this.config;
        // Baseline COUNT without a field includes null scores/ratings.
        var population = this._newAggregate();
        population.query();
        var populationCount = population.next() ? this._count(population.getAggregate('COUNT')) : 0;
        var aggregate = this._newAggregate();
        // Grouped database aggregation covers the whole population, not a sample.
        aggregate.groupBy(config.scoreField);
        aggregate.groupBy(config.ratingField);
        aggregate.query();
        var snapshot = { total: 0, invalidScores: 0, invalidRatings: 0, mismatches: 0, scoreSum: 0, ratingCounts: [0, 0, 0, 0, 0] };
        while (aggregate.next()) {
            var count = this._count(aggregate.getAggregate('COUNT'));
            if (count < 1) throw new Error('Empty aggregate group; no health result produced.');
            var scoreText = this._text(aggregate.getValue(config.scoreField));
            var ratingText = this._text(aggregate.getValue(config.ratingField));
            var score = Number(scoreText);
            var validScore = /^\d+$/.test(scoreText) && this._integer(score) && score >= config.scoreMinimum && score <= config.scoreMaximum;
            var ratingIndex = -1;
            for (var i = 0; i < config.ratings.length; i++) {
                if (config.ratings[i].value === ratingText) { ratingIndex = i; break; }
            }
            snapshot.total += count;
            if (!validScore) snapshot.invalidScores += count;
            else snapshot.scoreSum += score * count;
            if (ratingIndex < 0) snapshot.invalidRatings += count;
            else snapshot.ratingCounts[ratingIndex] += count;
            if (validScore && ratingIndex >= 0) {
                var rating = config.ratings[ratingIndex];
                if (score < rating.scoreMin || score > rating.scoreMax) snapshot.mismatches += count;
            }
        }
        var tolerance = config.populationCountTolerance;
        snapshot.populationCount = populationCount;
        snapshot.countDifference = Math.abs(snapshot.total - populationCount);
        snapshot.allowedCountDifference = Math.floor(populationCount * tolerance.maxDifferencePercent / 100);
        // All rating percentages and the mean use this SAME grouped snapshot total.
        return snapshot;
    },

    _newAggregate: function() {
        var aggregate = new GlideAggregate(this.config.table);
        for (var i = 0; i < this.config.filters.length; i++) {
            var filter = this.config.filters[i];
            aggregate.addQuery(filter.field, filter.operator, filter.value);
        }
        aggregate.addAggregate('COUNT');
        return aggregate;
    },
    _count: function(value) {
        var text = String(value);
        if (!/^\d+$/.test(text) || !this._integer(Number(text))) throw new Error('Invalid aggregate count; no health result produced.');
        return Number(text);
    },

    _validateField: function(record, field) {
        if (typeof field !== 'string' || !/^[a-zA-Z0-9_]+$/.test(field) || !record.isValidField(field))
            throw new Error('Invalid or unavailable direct field: ' + field);
    },
    _validateRange: function(min, max, lower, upper, name) {
        if (typeof min !== 'number' || typeof max !== 'number' || !isFinite(min) || !isFinite(max) || min < lower || max > upper || min > max)
            throw new Error(name + ' requires numeric min/max within ' + lower + '-' + upper + ', with min <= max.');
    },
    _integer: function(value) { return typeof value === 'number' && isFinite(value) && Math.floor(value) === value; },
    _array: function(value) { return Object.prototype.toString.call(value) === '[object Array]'; },
    _text: function(value) { return value === null || typeof value === 'undefined' ? '' : String(value).replace(/^\s+|\s+$/g, ''); },
    type: 'VRRiskDataHealth'
};
