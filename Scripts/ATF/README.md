# ATF test: VR risk score and rating health

Add **one test** named **VR - Risk score and rating health** to your existing suite, with the five server steps below. This checks existing VIT data: sufficient records, valid scores and ratings, correct score/rating mapping, and acceptable rating percentages. It does not create a suite, import test VITs, change data, or recalculate scores.

The [XML update set](VR_Risk_Data_Health_ATF.update-set.xml) imports the test, all five steps with their script inputs, and the shared Script Include. The JavaScript files remain available for review and maintenance.

## 1. Import the XML

1. Download [VR_Risk_Data_Health_ATF.update-set.xml](VR_Risk_Data_Health_ATF.update-set.xml) using GitHub's **Download raw file** control; save the XML, not the GitHub HTML page.
2. In your development or test instance, open **System Update Sets > Retrieved Update Sets > Import Update Set from XML**, choose the file, and upload it.
3. Open the retrieved update set **VR - Risk score and rating health - v2**, choose **Preview Update Set**, review any preview problems, and then **Commit Update Set**. The package contains seven customer updates: one Script Include, one test, and five steps (each step includes its input values).
4. Open **System Definition > Script Includes > VRRiskDataHealth** and configure the settings described below.
5. Open **Automated Test Framework > Tests > VR - Risk score and rating health** and verify the five ordered steps. Add that test to your **existing suite** using its Tests related list.

The package does not create a suite or suite membership because your suite's sys_id is instance-specific. It does not enable ATF execution, run the test, or modify VIT data. It uses the standard **Run Server Side Script** step configuration already installed with ATF; missing-reference preview problems must be resolved before committing. Local XML validation cannot replace preview and a live ATF run on your instance.

The test, helper and steps use stable IDs, so v2 updates the existing test and preserves its suite membership. Each package revision has its own retrieved-update-set ID. Reimporting updates the editable settings too: copy your existing configured ranges/settings before committing, then reapply them in the single configuration block. Step payloads use ServiceNow's SDK format to replace input values belonging only to those five steps.

The imported shared Script Include has these settings:

| Setting | Value |
| --- | --- |
| Name | `VRRiskDataHealth` |
| Application | Global |
| Active | Selected |
| Client callable | Not selected |
| Accessible from | This application scope only (all five steps run in Global) |
| Script | Entire contents of [VRRiskDataHealth.js](VRRiskDataHealth.js) |

Keep the generated class name and `type` as `VRRiskDataHealth`. **Every editable test setting lives together in `this.config`, inside `initialize`, between the ALL TEST SETTINGS and END OF ALL EDITABLE TEST SETTINGS banners.** All five steps use this same configuration; their scripts require no configuration edits.

## 2. Configure the population and acceptable ranges

Open **System Definition > Script Includes > VRRiskDataHealth**. Everything to review is in the one block at the top:

| Settings | What to configure |
| --- | --- |
| `configurationReviewed` | Set true after reviewing the block |
| `table`, `scoreField`, `ratingField` | VIT table and stored field names |
| `populationLabel`, `filters`, `minimumRecords` | Population description, selection and minimum size |
| `populationCountTolerance.maxDifferenceRecords` | Fixed record difference allowed; default `0` |
| `populationCountTolerance.maxDifferencePercent` | Percentage difference allowed; default `1` means 1% |
| `scoreMinimum`, `scoreMaximum` | Valid integer score domain |
| `ratings` | All five stored values, labels, score bands and accepted percentage ranges |
| `meanScore` | Optional minimum and maximum average score |

The defaults select **active records in `sn_vul_vulnerable_item`**, reading `risk_score` and `risk_rating`. Check that this is the population you intend to assess. `minimumRecords` starts at **100**, a configurable starting value rather than an organization-specific statistical guarantee.

**Count variance:** the separate count queries can see slightly different populations. The absolute difference is allowed up to the **larger** of `maxDifferenceRecords` and `floor(populationCount * maxDifferencePercent / 100)`. These allowances are not added together. With the default settings and a population count of 10,000, a grouped count from 9,900 through 10,100 is accepted. Set the percentage to `0` to use just a fixed record allowance, or set both to `0` to require exact equality. Both query counts must still meet `minimumRecords`. A difference within tolerance is shown in each affected step's output; a larger difference fails with both counts and the allowed difference.

The allowance handles a count discrepancy, not proof of its cause; it cannot distinguish concurrent updates from omitted groups. Use a tolerance appropriate to your data. Missing/invalid values present in the grouped results and score/rating mismatches still fail their checks.

For each entry in `ratings`, replace both `minPercent: null` and `maxPercent: null` with your accepted percentages on a **0 to 100 scale**. For example, `minPercent: 5, maxPercent: 15` means 5% through 15%, inclusive. That is a syntax example, not a recommended range. Zero is allowed, but null is not a configured threshold. Limits apply independently to all five categories, including categories with no records.

Use verified healthy data for the same population to select ranges, allowing for normal changes in asset mix and remediation. Do not establish ranges from the incident's artificially lowered scores. The script does not learn, update, or store a baseline. Missing ranges deliberately fail configuration instead of passing unchecked.

Confirm the stored rating values and integer score bands against your instance's risk score weights. The supplied mapping is the documented base mapping:

| Rating | Stored value | Integer score |
| --- | --- | --- |
| Critical | `1` | 90–100 |
| High | `2` | 70–89 |
| Medium | `3` | 40–69 |
| Low | `4` | 1–39 |
| None | `5` | 0 |

The domain and bands are editable but must cover a nonnegative integer domain exactly once. This implementation treats fractional scores as invalid; adapt the validation if your organization intentionally uses fractional scores. Blank scores are invalid, and a blank rating is **not** None.

Optionally set **both** `meanScore.min` and `meanScore.max` to acceptable mean-score bounds. This can catch downward score changes that stay within rating bands. Leave both null to display the mean as informational only. The mean is weighted by VIT counts, not by the number of distinct scores.

All population `filters` are ANDed, use direct field names and stored values, and are validated before any data query. Supported operators: `=`, `!=`, `IN`, `NOT IN`, `>`, `>=`, `<`, `<=`. For example, to check one source:

```javascript
populationLabel: 'Active VITs - chosen source',
filters: [
    { field: 'active', operator: '=', value: true },
    { field: 'source', operator: '=', value: 'YOUR_STORED_SOURCE_VALUE' }
],
```

To narrow to recently updated records, an additional direct `sys_updated_on` filter can use a literal UTC timestamp such as `2026-09-01 00:00:00`. This is an example, not a rolling window; edit it deliberately. Dot-walking, encoded queries, and `javascript:` expressions are not supported. Score/rating fields cannot be population filters because that could exclude unhealthy data from the check. Results apply only to this selected population and the execution context's domain/query visibility.

Finally, set **`configurationReviewed: true`** and save the Script Include. Configuration validation also rejects invalid fields, overlapping/gapped score bands, duplicate stored ratings, impossible percentage ranges, and partial mean-score bounds.

## 3. Imported test steps

The XML creates **VR - Risk score and rating health** under **Automated Test Framework > Tests**, in **Global**, with all five steps active. No new suite is created.

Each step uses **Server > Run Server Side Script**, **Application: Global**, and the complete script linked below. No copying/pasting is needed when importing the XML.

| Order | Check / Notes | Complete test script | Pass condition |
| --- | --- | --- | --- |
| 1 | Configuration and fields | [01-configuration.js](steps/01-configuration.js) | Reviewed configuration, all bounds configured, valid table/fields/filters and mappings |
| 2 | Population size | [02-population.js](steps/02-population.js) | Both counts meet `minimumRecords` and their difference is within the configured tolerance; empty data fails |
| 3 | Score and rating values | [03-values.js](steps/03-values.js) | No missing, noninteger, out-of-domain scores or blank/unknown ratings |
| 4 | Score/rating consistency | [04-consistency.js](steps/04-consistency.js) | Every score is inside the band for its stored rating |
| 5 | Rating distribution | [05-distribution.js](steps/05-distribution.js) | All five rating percentages, plus enabled mean-score bounds, are within inclusive limits |

No custom step configuration, cross-step output variables, browser steps, or Jasmine suites are needed. The scripts use the standard `assertEqual` assertion; a failed assertion fails the step and therefore the test. ATF normally stops at the failing step, so subsequent checks may not execute until that failure is fixed. Each later step repeats its prerequisites, so it cannot pass on insufficient, invalid, or inconsistent data if run separately.

## 4. Run and interpret

Run in **sub-production** after the integration import and risk recalculation have finished. Allow the required server-side reads from Global according to your instance's application access settings. Missing schema, query exceptions, or insufficient visible data fail the test; this is not an ACL coverage test.

The helper uses database aggregates over the **whole filtered population**, without loading every VIT or silently taking a sample. Each data step performs an ungrouped count and a grouped count by score/rating. A count difference beyond `populationCountTolerance` fails; an accepted difference is reported. Each step re-reads data; this is not a transactionally frozen snapshot, and equal-count updates can still happen between queries. Schedule it when imports and scoring are idle. Assess runtime against your instance's volume and ATF limits.

Failure output contains the population, record count, and only the failed checks or bounds. A healthy distribution prints one compact line with all five percentages and the mean. Percentages and mean use **the grouped snapshot total** as the denominator, including when a count difference is tolerated; the earlier count is used only for reconciliation and minimum-size checks. Invalid data found in the grouped results fails instead of being discarded. Comparison uses unrounded values; displayed values are rounded.

Example failure (illustrative values only):

```text
Fail | Active VITs | VITs: 10000
Critical: 0.0000% (0/10000); expected 5-15%
None: 80.0000% (8000/10000); expected 0-2%
```

These checks detect suspicious data, not the cause of an integration defect. An enterprise-wide distribution can hide a problem confined to one source, and incorrect scores can still fall within accepted ranges. The optional mean bounds improve coverage but do not independently verify calculator inputs or the scoring formula. This test does not retrieve the external integration payload or check individual required input fields.

## References and local verification

- [ServiceNow ATF server steps](https://www.servicenow.com/docs/r/application-development/automated-test-framework-atf/test-steps-server-category.html): Run Server Side Script and assertions.
- [Run an automated test](https://www.servicenow.com/docs/r/application-development/automated-test-framework-atf/atf-run-test.html): sub-production execution and test results.
- [VR calculators and risk score weights](https://www.servicenow.com/docs/r/security-management/vulnerability-response/vuln-calculators-rules.html): configurable scoring and base rating bands.
- [GlideAggregate API](https://www.servicenow.com/docs/r/api-reference/server-api-reference/c_GlideAggregateAPI.html): counts and grouping.
- [GlideRecord API](https://www.servicenow.com/docs/r/xanadu/api-reference/server-api-reference/c_GlideRecordAPI.html): invalid-query handling, motivating field validation.
- [Import an update set XML](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_SaveAnUpdateSetAsAnXMLFile.html) and [preview an update set](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_PreviewARemoteUpdateSet.html).
- Official [ServiceNow SDK build plugins 4.13.0](https://www.npmjs.com/package/@servicenow/sdk-build-plugins/v/4.13.0), `src/atf/step-configs.ts` and `src/atf/test-plugin.ts`: step configuration IDs, script/Jasmine input IDs, and embedded `sys_variable_value` serialization. The XML references the installed OOB configuration; it does not overwrite it.
- [ServiceNow's published update set example](https://github.com/ServiceNow/example-restclient-myworkapp-nodejs/blob/6e4b93759c45b1d33a2515e40af049f6b784d8f0/mywork_update_set/sys_remote_update_set_2f48a7d74f4652002fa02f1e0210c785.xml): retrieved update set envelope and customer-update payload format.

The XML is generated from the JavaScript source files. After editing repository source, rebuild it before importing:

```sh
python3 tools/build_vr_atf_xml.py
python3 tools/build_vr_atf_xml.py --check
python3 tests/vr-atf-xml.test.py
node tests/vr-risk-data-health.test.js
node tests/application-health-scan.test.js
```

Local tests mock ServiceNow APIs. Live ATF execution and verification of your instance-specific fields, access, domain, bands, thresholds and runtime are still required.
