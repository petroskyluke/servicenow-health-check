(function applicationHealthScan() {

    /********************************************************************
     * CONFIGURATION
     ********************************************************************/
    // Use sys_scope.scope values, not application display labels.
    // Add multiple names to scan them in one run, e.g. ['sn_sec_cmn', 'sn_vul'].
    var appNames = ['sn_sec_cmn'];

    var tables = [
        'sys_script_client',  // Client Scripts
        'sys_script',         // Business Rules
        'sys_ui_action',      // UI Actions
        'sys_script_include', // Script Includes
        'sysauto_script'      // Scheduled Script Executions
    ];

    /*
     * Patterns are intentionally static-code checks.
     *
     * sysIdRegex:
     * Finds standalone 32-character hexadecimal values.
     *
     * gsInfoRegex:
     * Finds gs.info( calls, with optional whitespace.
     *
     * grVariableRegex:
     * Finds declarations named exactly "gr" (case-insensitive).
     * Flags var gr, let GR, const Gr; allows grMembers, grTask, gr1, gr$.
     * This check also runs on untouched OOB records in the selected scopes.
     *
     * currentUpdateRegex:
     * Finds current.update( calls.
     */
    var sysIdRegex = /\b[a-f0-9]{32}\b/gi;
    var gsInfoRegex = /\bgs\s*\.\s*info\s*\(/gi;
    var grVariableRegex = /\b(?:var|let|const)\s+(gr)(?![A-Za-z0-9_$\u0080-\uFFFF])/gi;
    var currentUpdateRegex = /\bcurrent\s*\.\s*update\s*\(/gi;

    var seenApps = {};
    var applicationsScanned = 0;
    var customerUpdateLookupAvailable = hasCustomerUpdateMetadata();

    if (!customerUpdateLookupAvailable) {
        gs.print('Scan stopped: customer-update metadata is unavailable; cannot safely select custom records.');
        return;
    }

    for (var appIndex = 0; appIndex < appNames.length; appIndex++) {
        var appName = String(appNames[appIndex] || '').replace(/^\s+|\s+$/g, '');
        if (!appName || seenApps['scope:' + appName]) {
            continue;
        }
        seenApps['scope:' + appName] = true;
        scanApplication(appName);
    }

    if (applicationsScanned === 0) {
        gs.print('No applications scanned. Check appNames (sys_scope.scope values).');
    }

    function scanApplication(appName) {
        var scopeGR = new GlideRecord('sys_scope');
        scopeGR.addQuery('scope', appName);
        scopeGR.setLimit(2);
        scopeGR.query();

        if (!scopeGR.next()) {
            gs.print('Application not found: ' + appName);
            return;
        }

        var scopeId = scopeGR.getUniqueValue();
        if (scopeGR.next()) {
            gs.print('Application skipped: ' + appName + ' | Multiple matching scopes.');
            return;
        }
        applicationsScanned++;

        /********************************************************************
         * RESULTS
         ********************************************************************/
        var results = {};
        var grandTotals = {
            recordsScanned: 0,

            sysIdOccurrences: 0,
            uniqueSysIds: {},
            recordsWithSysIds: 0,

            gsInfoOccurrences: 0,
            recordsWithGsInfo: 0,

            grVariableOccurrences: 0,
            uniqueGrVariables: {},
            recordsWithGrVariables: 0,

            currentUpdateOccurrences: 0,
            businessRulesWithCurrentUpdate: 0,

            activeJobsRunByInactiveUsers: 0
        };

        var details = {
            sysIds: [],
            gsInfo: [],
            grVariables: [],
            currentUpdate: [],
            inactiveRunAs: [],
            skippedTables: [],
            warnings: []
        };

        /********************************************************************
         * SCAN EACH SCRIPT TABLE
         ********************************************************************/
        for (var i = 0; i < tables.length; i++) {
            var tableName = tables[i];

            results[tableName] = {
                recordsScanned: 0,

                sysIdOccurrences: 0,
                uniqueSysIds: {},
                recordsWithSysIds: 0,

                gsInfoOccurrences: 0,
                recordsWithGsInfo: 0,

                grVariableOccurrences: 0,
                uniqueGrVariables: {},
                recordsWithGrVariables: 0,

                currentUpdateOccurrences: 0,
                recordsWithCurrentUpdate: 0,

                activeJobsRunByInactiveUsers: 0
            };

            var recordGR = new GlideRecord(tableName);

            if (!recordGR.isValid()) {
                details.skippedTables.push(
                    tableName + ' | Table is not available.'
                );
                continue;
            }

            /*
             * Do not scan an entire table if it cannot be safely restricted
             * to the selected application.
             */
            if (!recordGR.isValidField('sys_scope')) {
                details.skippedTables.push(
                    tableName + ' | sys_scope field is not available.'
                );
                continue;
            }

            recordGR.addQuery('sys_scope', scopeId);
            recordGR.query();

            while (recordGR.next()) {

                // Exact-gr applies to every record in scope. Other checks retain
                // their customer-created/customer-modified selection.
                var customerChanged = isCustomerCreatedOrModified(recordGR, tableName);
                var script = recordGR.isValidField('script')
                    ? (recordGR.getValue('script') || '') : '';
                var grMatches = script.match(grVariableRegex) || [];
                results[tableName].recordsScanned++;
                grandTotals.recordsScanned++;
                if (!customerChanged && grMatches.length === 0) {
                    continue;
                }

                var recordOrigin = getRecordOrigin(recordGR, tableName, customerChanged);
                var recordLabel = getRecordLabel(recordGR);
                var recordId = recordGR.getUniqueValue();
                var recordContext = tableName + ' | ' + recordLabel +
                    ' | record: ' + recordId +
                    ' | origin: ' + recordOrigin;

                /*
                 * Scheduled job validation does not depend only on the
                 * contents of the script field.
                 */
                if (customerChanged && tableName == 'sysauto_script') {
                    checkScheduledJob(
                        recordGR,
                        tableName,
                        recordContext,
                        results,
                        details,
                        grandTotals
                    );
                }

                if (!recordGR.isValidField('script')) {
                    continue;
                }

                /************************************************************
                 * HARD-CODED SYS_IDS
                 ************************************************************/
                var sysIdMatches = customerChanged ? script.match(sysIdRegex) : null;

                if (sysIdMatches && sysIdMatches.length > 0) {
                    var recordSysIds = {};
                    var normalizedSysIds = [];

                    results[tableName].recordsWithSysIds++;
                    grandTotals.recordsWithSysIds++;

                    for (var s = 0; s < sysIdMatches.length; s++) {
                        var sysId = sysIdMatches[s].toLowerCase();

                        results[tableName].sysIdOccurrences++;
                        grandTotals.sysIdOccurrences++;

                        results[tableName].uniqueSysIds[sysId] = true;
                        grandTotals.uniqueSysIds[sysId] = true;

                        if (!recordSysIds[sysId]) {
                            recordSysIds[sysId] = true;
                            normalizedSysIds.push(sysId);
                        }
                    }

                    details.sysIds.push(
                        recordContext +
                        ' | occurrences: ' + sysIdMatches.length +
                        ' | unique in record: ' + normalizedSysIds.length +
                        ' | values: ' + normalizedSysIds.join(', ')
                    );
                }

                /************************************************************
                 * GS.INFO()
                 ************************************************************/
                var gsInfoMatches = customerChanged ? script.match(gsInfoRegex) : null;

                if (gsInfoMatches && gsInfoMatches.length > 0) {
                    results[tableName].gsInfoOccurrences += gsInfoMatches.length;
                    results[tableName].recordsWithGsInfo++;

                    grandTotals.gsInfoOccurrences += gsInfoMatches.length;
                    grandTotals.recordsWithGsInfo++;

                    details.gsInfo.push(
                        recordContext +
                        ' | gs.info() occurrences: ' + gsInfoMatches.length
                    );
                }

                /************************************************************
                 * VARIABLES NAMED EXACTLY "gr"
                 ************************************************************/
                var recordGrVariables = {};
                var grVariableOccurrences = 0;
                var grMatch;

                /*
                 * Reset lastIndex because this regular expression uses the
                 * global flag and is reused for multiple records.
                 */
                grVariableRegex.lastIndex = 0;

                while ((grMatch = grVariableRegex.exec(script)) !== null) {
                    var variableName = grMatch[1];

                    grVariableOccurrences++;
                    recordGrVariables[variableName] = true;
                    results[tableName].uniqueGrVariables[variableName] = true;
                    grandTotals.uniqueGrVariables[variableName] = true;
                }

                if (grVariableOccurrences > 0) {
                    var recordVariableNames = objectKeys(recordGrVariables);

                    results[tableName].grVariableOccurrences += grVariableOccurrences;
                    results[tableName].recordsWithGrVariables++;

                    grandTotals.grVariableOccurrences += grVariableOccurrences;
                    grandTotals.recordsWithGrVariables++;

                    var grPriority = recordOrigin == 'UPMC custom' ? 'SEVERE' : 'LOW';
                    details.grVariables.push(
                        recordContext +
                        ' | priority: ' + grPriority +
                        ' | exact-gr declarations: ' + grVariableOccurrences +
                        ' | names: ' + recordVariableNames.join(', ')
                    );
                }

                /************************************************************
                 * CURRENT.UPDATE() IN BUSINESS RULES
                 ************************************************************/
                if (customerChanged && tableName == 'sys_script') {
                    var currentUpdateMatches = script.match(currentUpdateRegex);

                    if (currentUpdateMatches && currentUpdateMatches.length > 0) {
                        results[tableName].currentUpdateOccurrences +=
                            currentUpdateMatches.length;

                        results[tableName].recordsWithCurrentUpdate++;

                        grandTotals.currentUpdateOccurrences +=
                            currentUpdateMatches.length;

                        grandTotals.businessRulesWithCurrentUpdate++;

                        details.currentUpdate.push(
                            recordContext +
                            ' | current.update() occurrences: ' +
                            currentUpdateMatches.length +
                            ' | active: ' + getFieldValue(recordGR, 'active') +
                            ' | when: ' + getFieldValue(recordGR, 'when') +
                            ' | order: ' + getFieldValue(recordGR, 'order')
                        );
                    }
                }
            }
        }

        /********************************************************************
         * OUTPUT: omit empty tables, zero counters, and empty detail sections.
         ********************************************************************/
        gs.print('');
        gs.print('Application: ' + appName + ' | Scope sys_id: ' + scopeId +
            ' | Records scanned: ' + grandTotals.recordsScanned);

        var hasFindings = false;
        for (var t = 0; t < tables.length; t++) {
            var summaryTable = tables[t];
            var tableResult = results[summaryTable];
            var counts = [];
            addCount(counts, 'hard-coded sys_ids', tableResult.sysIdOccurrences);
            addCount(counts, 'gs.info()', tableResult.gsInfoOccurrences);
            addCount(counts, 'Exact "gr" declarations', tableResult.grVariableOccurrences);
            addCount(counts, 'current.update()', tableResult.currentUpdateOccurrences);
            addCount(counts, 'inactive Run as users', tableResult.activeJobsRunByInactiveUsers);
            if (counts.length === 0) {
                continue;
            }
            hasFindings = true;
            gs.print(summaryTable + ' | ' + counts.join(' | '));
        }

        printDetailSection('Hard-coded sys_ids', details.sysIds);
        printDetailSection('gs.info()', details.gsInfo);
        printDetailSection('Exact "gr" declarations', details.grVariables);
        printDetailSection('current.update()', details.currentUpdate);
        printDetailSection('Inactive Run as users', details.inactiveRunAs);
        printDetailSection('Skipped tables', details.skippedTables);
        printDetailSection('Warnings', details.warnings);

        if (!hasFindings) {
            gs.print(details.skippedTables.length || details.warnings.length
                ? 'No findings in completed checks; see warnings/skipped tables.'
                : 'No findings.');
        }
    }

    /********************************************************************
     * SCHEDULED JOB CHECK
     ********************************************************************/
    function checkScheduledJob(
        jobGR,
        tableName,
        recordContext,
        allResults,
        allDetails,
        totals
    ) {
        if (!jobGR.isValidField('active')) {
            allDetails.warnings.push(
                recordContext +
                ' | active field is not available.'
            );
            return;
        }

        if (jobGR.getValue('active') != '1') {
            return;
        }

        if (!jobGR.isValidField('run_as')) {
            allDetails.warnings.push(
                recordContext +
                ' | run_as field is not available.'
            );
            return;
        }

        var runAsUserId = jobGR.getValue('run_as');

        /*
         * A blank Run as value is reported as a warning rather than
         * classified as an inactive user.
         */
        if (!runAsUserId) {
            allDetails.warnings.push(
                recordContext +
                ' | Active scheduled job has no Run as user.'
            );
            return;
        }

        var userGR = new GlideRecord('sys_user');

        if (!userGR.get(runAsUserId)) {
            allDetails.warnings.push(
                recordContext +
                ' | Run as user record was not found: ' + runAsUserId
            );
            return;
        }

        if (userGR.getValue('active') != '1') {
            allResults[tableName].activeJobsRunByInactiveUsers++;
            totals.activeJobsRunByInactiveUsers++;

            allDetails.inactiveRunAs.push(
                recordContext +
                ' | Run as user: ' + userGR.getDisplayValue() +
                ' | user sys_id: ' + runAsUserId +
                ' | user active: false'
            );
        }
    }

    /********************************************************************
     * HELPER FUNCTIONS
     ********************************************************************/
    function getRecordLabel(record) {
        var labelFields = [
            'name',
            'short_description',
            'description',
            'action_name'
        ];

        for (var i = 0; i < labelFields.length; i++) {
            var fieldName = labelFields[i];

            if (record.isValidField(fieldName)) {
                var value = record.getDisplayValue(fieldName);

                if (value) {
                    return value;
                }
            }
        }

        var displayValue = record.getDisplayValue();

        if (displayValue) {
            return displayValue;
        }

        return record.getUniqueValue();
    }

    function getFieldValue(record, fieldName) {
        if (!record.isValidField(fieldName)) {
            return 'N/A';
        }

        var value = record.getDisplayValue(fieldName);

        if (value === null || value === '') {
            return '(blank)';
        }

        return value;
    }

    function hasCustomerUpdateMetadata() {
        var updateGR = new GlideRecord('sys_update_xml');
        var requiredFields = ['name', 'category', 'action', 'update_set', 'remote_update_set'];
        if (!updateGR.isValid()) {
            return false;
        }
        for (var i = 0; i < requiredFields.length; i++) {
            if (!updateGR.isValidField(requiredFields[i])) {
                return false;
            }
        }
        return true;
    }

    function isCustomerCreatedOrModified(recordGR, tableName) {
        // Use the platform's customer-update marker when exposed on the record.
        // Do not infer ownership from creator names, dates, or modification counts.
        if (recordGR.isValidField('sys_customer_update')) {
            var customerUpdate = recordGR.getValue('sys_customer_update');
            if (customerUpdate == '1' || customerUpdate == 'true') {
                return true;
            }
        }

        var updateName = getUpdateName(recordGR, tableName);

        var updateGR = new GlideRecord('sys_update_xml');
        updateGR.addQuery('name', updateName);
        updateGR.addQuery('category', 'customer');
        // Retrieved/previewed updates are not evidence of a local customization.
        // Committed remote updates have a local update-set copy.
        updateGR.addNotNullQuery('update_set');
        updateGR.addNullQuery('remote_update_set');
        updateGR.orderByDesc('sys_updated_on');
        updateGR.setLimit(1);
        updateGR.query();

        if (!updateGR.next()) {
            return false;
        }
        var action = updateGR.getValue('action');
        return action == 'INSERT' || action == 'UPDATE' || action == 'INSERT_OR_UPDATE';
    }

    function getUpdateName(recordGR, tableName) {
        // Both newly created and modified OOB files are captured as customer updates.
        // The update name is normally <table>_<sys_id>, not a bare sys_id.
        var updateName = recordGR.isValidField('sys_update_name')
            ? recordGR.getValue('sys_update_name') : '';
        if (!updateName) {
            var recordClass = recordGR.isValidField('sys_class_name')
                ? recordGR.getValue('sys_class_name') : '';
            updateName = (recordClass || tableName) + '_' + recordGR.getUniqueValue();
        }

        return updateName;
    }

    function getRecordOrigin(recordGR, tableName, customerChanged) {
        // Per UPMC reporting policy, unresolved customer-changed origins are
        // treated as UPMC custom. This is a reporting assumption, not proof
        // of authorship. No tracked customer changes means OOB-only GR review.
        var fallback = customerChanged ? 'UPMC custom' : 'OOB/Store (no customer changes tracked)';
        try {
            var versionGR = new GlideRecord('sys_update_version');
            if (!versionGR.isValid() || !versionGR.isValidField('name') ||
                    !versionGR.isValidField('source_table')) {
                return fallback;
            }
            versionGR.addQuery('name', getUpdateName(recordGR, tableName));
            versionGR.addQuery('source_table', 'IN', 'sys_upgrade_history,sys_store_app');
            versionGR.setLimit(1);
            versionGR.query();
            if (versionGR.next()) {
                return customerChanged ? 'Customized OOB/Store file' : 'OOB/Store file';
            }
        } catch (error) {
            // Keep findings and apply the configured reporting policy.
        }
        return fallback;
    }

    function objectKeys(object) {
        var keys = [];

        for (var key in object) {
            if (object.hasOwnProperty(key)) {
                keys.push(key);
            }
        }

        keys.sort();
        return keys;
    }

    function addCount(counts, label, count) {
        if (count > 0) {
            counts.push(label + ': ' + count);
        }
    }

    function printDetailSection(title, items) {
        if (items.length === 0) {
            return;
        }
        gs.print(title + ':');
        for (var i = 0; i < items.length; i++) {
            gs.print('  ' + items[i]);
        }
    }

})();
