/*
 * Global, server-only Script Include: VRRiskDataHealth
 * One ATF test uses this helper from the five scripts in steps/.
 * Reads existing VITs only; never updates records or recalculates risk.
 * Setup and sources: README.md in this directory.
 */
var VRRiskDataHealth = Class.create();
VRRiskDataHealth.prototype = {
    initialize: function() {
        /**************************************************************
         * EDIT THESE SETTINGS BEFORE RUNNING THE ATF TEST.
         * Percentage ranges are deliberately unset, not recommendations.
         * Use a verified healthy population to decide acceptable ranges.
         **************************************************************/
        this.config = {
            configurationReviewed: false, // Set true after reviewing ALL settings.
            table: 'sn_vul_vulnerable_item',
            scoreField: 'risk_score',
            ratingField: 'risk_rating',
            populationLabel: 'Active VITs',
            // Direct fields only; all conditions are ANDed. Use stored values.
            filters: [
                { field: 'active', operator: '=', value: true }
                // Example: { field: 'source', operator: '=', value: 'YOUR_SOURCE' }
            ],
            minimumRecords: 100, // Choose a meaningful minimum for this population.
            // Integer score domain and rating bands must match YOUR instance.
            scoreMinimum: 0,
            scoreMaximum: 100,
            ratings: [
                { value: '1', label: 'Critical', scoreMin: 90, scoreMax: 100, minPercent: null, maxPercent: null },
                { value: '2', label: 'High',     scoreMin: 70, scoreMax: 89,  minPercent: null, maxPercent: null },
                { value: '3', label: 'Medium',   scoreMin: 40, scoreMax: 69,  minPercent: null, maxPercent: null },
                { value: '4', label: 'Low',      scoreMin: 1,  scoreMax: 39,  minPercent: null, maxPercent: null },
                { value: '5', label: 'None',     scoreMin: 0,  scoreMax: 0,   minPercent: null, maxPercent: null }
            ],
            // Optional: helps catch lower scores even within the same rating.
            // Both null disables this extra check; otherwise set BOTH bounds.
            meanScore: { min: null, max: null }
        };
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
            if (snapshot.total < this.config.minimumRecords)
                return { passed: false, message: 'Fail | ' + prefix + ' | Insufficient data; minimum: ' + this.config.minimumRecords };
            if (check === 'population')
                return { passed: true, message: 'Pass | ' + prefix };

            var valueFailures = [];
            if (snapshot.invalidScores) valueFailures.push('Missing/invalid scores: ' + snapshot.invalidScores);
            if (snapshot.invalidRatings) valueFailures.push('Missing/invalid ratings: ' + snapshot.invalidRatings);
            // Never calculate a healthy distribution by silently dropping bad data.
            if (valueFailures.length)
                return { passed: false, message: 'Fail | ' + prefix + ' | ' + valueFailures.join(' | ') };
            if (check === 'values')
                return { passed: true, message: 'Pass | ' + prefix + ' | Scores and ratings valid.' };

            if (snapshot.mismatches)
                return { passed: false, message: 'Fail | ' + prefix + ' | Score/rating mismatches: ' + snapshot.mismatches };
            if (check === 'consistency')
                return { passed: true, message: 'Pass | ' + prefix + ' | Score/rating bands match.' };

            var failures = [];
            var percentages = [];
            for (var i = 0; i < this.config.ratings.length; i++) {
                var rating = this.config.ratings[i];
                var percent = 100 * snapshot.ratingCounts[i] / snapshot.total;
                percentages.push(rating.label + ': ' + percent.toFixed(2) + '%');
                // Compare full precision; rounding is for display only.
                if (percent < rating.minPercent || percent > rating.maxPercent)
                    failures.push(rating.label + ': ' + percent.toFixed(4) + '% (' + snapshot.ratingCounts[i] + '/' + snapshot.total + '); expected ' + rating.minPercent + '-' + rating.maxPercent + '%');
            }
            var mean = snapshot.scoreSum / snapshot.total;
            var bounds = this.config.meanScore;
            if (bounds.min !== null && (mean < bounds.min || mean > bounds.max))
                failures.push('Mean score: ' + mean.toFixed(4) + '; expected ' + bounds.min + '-' + bounds.max);
            if (failures.length)
                return { passed: false, message: 'Fail | ' + prefix + '\n' + failures.join('\n') };
            return { passed: true, message: 'Pass | ' + prefix + ' | ' + percentages.join(' | ') + ' | Mean score: ' + mean.toFixed(2) + (bounds.min === null ? ' (informational)' : '') };
        } catch (error) {
            return { passed: false, message: 'Fail | ' + String(error.message || error) };
        }
    },

    _validateConfiguration: function() {
        var config = this.config;
        if (config.configurationReviewed !== true)
            throw new Error('Review population, score bands, percentage ranges and minimumRecords; then set configurationReviewed to true.');
        if (!this._integer(config.minimumRecords) || config.minimumRecords < 1)
            throw new Error('minimumRecords must be a positive integer.');
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
        // Authoritative COUNT without a field includes null scores/ratings.
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
        if (snapshot.total !== populationCount)
            throw new Error('Population changed or grouped results are incomplete; total: ' + populationCount + ', grouped: ' + snapshot.total + '. Retry after imports and recalculation finish.');
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
