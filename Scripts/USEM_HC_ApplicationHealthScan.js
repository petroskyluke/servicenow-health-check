(function applicationHealthScan() {

    /********************************************************************
     * CONFIGURATION
     ********************************************************************/
    var appName = 'Unified Security Exposure Management';

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
     * Finds declared variables whose names begin with "gr".
     * Examples:
     *   var grIncident
     *   let grTask
     *   const grUser
     *
     * currentUpdateRegex:
     * Finds current.update( calls.
     */
    var sysIdRegex = /\b[a-f0-9]{32}\b/gi;
    var gsInfoRegex = /\bgs\s*\.\s*info\s*\(/gi;
    var grVariableRegex = /\b(?:var|let|const)\s+(gr[A-Za-z0-9_$]*)\b/g;
    var currentUpdateRegex = /\bcurrent\s*\.\s*update\s*\(/gi;

    /********************************************************************
     * FIND APPLICATION SCOPE
     ********************************************************************/
    var scopeGR = new GlideRecord('sys_scope');
    scopeGR.addQuery('name', appName);
    scopeGR.setLimit(2);
    scopeGR.query();

    if (!scopeGR.next()) {
        gs.print('');
        gs.print('APPLICATION HEALTH SCAN');
        gs.print('Application not found: ' + appName);
        return;
    }

    var scopeId = scopeGR.getUniqueValue();
    var scopeName = scopeGR.getDisplayValue();

    if (scopeGR.next()) {
        gs.print('');
        gs.print('WARNING: More than one sys_scope record was found with the name: ' + appName);
        gs.print('The scan will use the first matching scope.');
    }

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

            // Skip records that have never been customized
            if (!isCustomized(recordGR))
                continue;

            results[tableName].recordsScanned++;
            grandTotals.recordsScanned++;

            var recordLabel = getRecordLabel(recordGR);
            var recordId = recordGR.getUniqueValue();

            /*
             * Scheduled job validation does not depend only on the
             * contents of the script field.
             */
            if (tableName == 'sysauto_script') {
                checkScheduledJob(
                    recordGR,
                    tableName,
                    recordLabel,
                    recordId,
                    results,
                    details,
                    grandTotals
                );
            }

            if (!recordGR.isValidField('script')) {
                continue;
            }

            var script = recordGR.getValue('script') || '';

            /************************************************************
             * HARD-CODED SYS_IDS
             ************************************************************/
            var sysIdMatches = script.match(sysIdRegex);

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
                    tableName +
                    ' | ' + recordLabel +
                    ' | record: ' + recordId +
                    ' | occurrences: ' + sysIdMatches.length +
                    ' | unique in record: ' + normalizedSysIds.length +
                    ' | values: ' + normalizedSysIds.join(', ')
                );
            }

            /************************************************************
             * GS.INFO()
             ************************************************************/
            var gsInfoMatches = script.match(gsInfoRegex);

            if (gsInfoMatches && gsInfoMatches.length > 0) {
                results[tableName].gsInfoOccurrences += gsInfoMatches.length;
                results[tableName].recordsWithGsInfo++;

                grandTotals.gsInfoOccurrences += gsInfoMatches.length;
                grandTotals.recordsWithGsInfo++;

                details.gsInfo.push(
                    tableName +
                    ' | ' + recordLabel +
                    ' | record: ' + recordId +
                    ' | gs.info() occurrences: ' + gsInfoMatches.length
                );
            }

            /************************************************************
             * VARIABLES BEGINNING WITH "gr"
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

                details.grVariables.push(
                    tableName +
                    ' | ' + recordLabel +
                    ' | record: ' + recordId +
                    ' | declarations: ' + grVariableOccurrences +
                    ' | unique variables: ' + recordVariableNames.length +
                    ' | names: ' + recordVariableNames.join(', ')
                );
            }

            /************************************************************
             * CURRENT.UPDATE() IN BUSINESS RULES
             ************************************************************/
            if (tableName == 'sys_script') {
                var currentUpdateMatches = script.match(currentUpdateRegex);

                if (currentUpdateMatches && currentUpdateMatches.length > 0) {
                    results[tableName].currentUpdateOccurrences +=
                        currentUpdateMatches.length;

                    results[tableName].recordsWithCurrentUpdate++;

                    grandTotals.currentUpdateOccurrences +=
                        currentUpdateMatches.length;

                    grandTotals.businessRulesWithCurrentUpdate++;

                    details.currentUpdate.push(
                        tableName +
                        ' | ' + recordLabel +
                        ' | record: ' + recordId +
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
     * OUTPUT
     ********************************************************************/
    printHeader('APPLICATION HEALTH SCAN');

    gs.print('Application: ' + scopeName);
    gs.print('Scope sys_id: ' + scopeId);
    gs.print('Tables requested: ' + tables.length);
    gs.print('Total records scanned: ' + grandTotals.recordsScanned);

    printHeader('OVERALL SUMMARY');

    gs.print(
        'Hard-coded sys_id occurrences: ' +
        grandTotals.sysIdOccurrences
    );

    gs.print(
        'Unique hard-coded sys_ids: ' +
        countObjectKeys(grandTotals.uniqueSysIds)
    );

    gs.print(
        'Records containing hard-coded sys_ids: ' +
        grandTotals.recordsWithSysIds
    );

    gs.print(
        'gs.info() occurrences: ' +
        grandTotals.gsInfoOccurrences
    );

    gs.print(
        'Records containing gs.info(): ' +
        grandTotals.recordsWithGsInfo
    );

    gs.print(
        'Variables beginning with "gr": ' +
        grandTotals.grVariableOccurrences
    );

    gs.print(
        'Unique variable names beginning with "gr": ' +
        countObjectKeys(grandTotals.uniqueGrVariables)
    );

    gs.print(
        'Records containing variables beginning with "gr": ' +
        grandTotals.recordsWithGrVariables
    );

    gs.print(
        'current.update() occurrences in Business Rules: ' +
        grandTotals.currentUpdateOccurrences
    );

    gs.print(
        'Business Rules containing current.update(): ' +
        grandTotals.businessRulesWithCurrentUpdate
    );

    gs.print(
        'Active scheduled jobs run by inactive users: ' +
        grandTotals.activeJobsRunByInactiveUsers
    );

    printHeader('SUMMARY BY TABLE');

    for (var t = 0; t < tables.length; t++) {
        var summaryTable = tables[t];
        var tableResult = results[summaryTable];

        gs.print('');
        gs.print('Table: ' + summaryTable);
        gs.print('  Records scanned: ' + tableResult.recordsScanned);

        gs.print(
            '  Hard-coded sys_id occurrences: ' +
            tableResult.sysIdOccurrences
        );

        gs.print(
            '  Unique hard-coded sys_ids: ' +
            countObjectKeys(tableResult.uniqueSysIds)
        );

        gs.print(
            '  Records with hard-coded sys_ids: ' +
            tableResult.recordsWithSysIds
        );

        gs.print(
            '  gs.info() occurrences: ' +
            tableResult.gsInfoOccurrences
        );

        gs.print(
            '  Records with gs.info(): ' +
            tableResult.recordsWithGsInfo
        );

        gs.print(
            '  "gr" variable declarations: ' +
            tableResult.grVariableOccurrences
        );

        gs.print(
            '  Unique "gr" variable names: ' +
            countObjectKeys(tableResult.uniqueGrVariables)
        );

        gs.print(
            '  Records with "gr" variables: ' +
            tableResult.recordsWithGrVariables
        );

        if (summaryTable == 'sys_script') {
            gs.print(
                '  current.update() occurrences: ' +
                tableResult.currentUpdateOccurrences
            );

            gs.print(
                '  Business Rules with current.update(): ' +
                tableResult.recordsWithCurrentUpdate
            );
        }

        if (summaryTable == 'sysauto_script') {
            gs.print(
                '  Active jobs run by inactive users: ' +
                tableResult.activeJobsRunByInactiveUsers
            );
        }
    }

    printDetailSection(
        'HARD-CODED SYS_ID DETAILS',
        details.sysIds,
        'No hard-coded sys_ids found.'
    );

    printDetailSection(
        'GS.INFO() DETAILS',
        details.gsInfo,
        'No gs.info() calls found.'
    );

    printDetailSection(
        'VARIABLES BEGINNING WITH "gr"',
        details.grVariables,
        'No declared variables beginning with "gr" found.'
    );

    printDetailSection(
        'CURRENT.UPDATE() IN BUSINESS RULES',
        details.currentUpdate,
        'No current.update() calls found in Business Rules.'
    );

    printDetailSection(
        'ACTIVE SCHEDULED JOBS RUN BY INACTIVE USERS',
        details.inactiveRunAs,
        'No active scheduled jobs run by inactive users found.'
    );

    printDetailSection(
        'SKIPPED TABLES',
        details.skippedTables,
        'No tables were skipped.'
    );

    printDetailSection(
        'WARNINGS',
        details.warnings,
        'No scan warnings.'
    );

    printHeader('SCAN COMPLETE');

    /********************************************************************
     * SCHEDULED JOB CHECK
     ********************************************************************/
    function checkScheduledJob(
        jobGR,
        tableName,
        recordLabel,
        recordId,
        allResults,
        allDetails,
        totals
    ) {
        if (!jobGR.isValidField('active')) {
            allDetails.warnings.push(
                tableName +
                ' | ' + recordLabel +
                ' | active field is not available.'
            );
            return;
        }

        if (jobGR.getValue('active') != '1') {
            return;
        }

        if (!jobGR.isValidField('run_as')) {
            allDetails.warnings.push(
                tableName +
                ' | ' + recordLabel +
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
                tableName +
                ' | ' + recordLabel +
                ' | record: ' + recordId +
                ' | Active scheduled job has no Run as user.'
            );
            return;
        }

        var userGR = new GlideRecord('sys_user');

        if (!userGR.get(runAsUserId)) {
            allDetails.warnings.push(
                tableName +
                ' | ' + recordLabel +
                ' | record: ' + recordId +
                ' | Run as user record was not found: ' + runAsUserId
            );
            return;
        }

        if (userGR.getValue('active') != '1') {
            allResults[tableName].activeJobsRunByInactiveUsers++;
            totals.activeJobsRunByInactiveUsers++;

            allDetails.inactiveRunAs.push(
                tableName +
                ' | ' + recordLabel +
                ' | record: ' + recordId +
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

    function isCustomized(recordGR) {
        var metadataId = recordGR.getUniqueValue();

        var versionGR = new GlideRecord('sys_update_version');
        versionGR.addQuery('name', metadataId);
        versionGR.setLimit(1);
        versionGR.query();

        return versionGR.hasNext();
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

    function countObjectKeys(object) {
        return objectKeys(object).length;
    }

    function printHeader(title) {
        gs.print('');
        gs.print('============================================================');
        gs.print(title);
        gs.print('============================================================');
    }

    function printDetailSection(title, items, emptyMessage) {
        printHeader(title);

        if (items.length === 0) {
            gs.print(emptyMessage);
            return;
        }

        gs.print('Finding count: ' + items.length);
        gs.print('');

        for (var i = 0; i < items.length; i++) {
            gs.print((i + 1) + '. ' + items[i]);
        }
    }

})();