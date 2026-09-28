# CMPNY VR: Risk score and rating health - USEM

One read-only ATF test with five server-side steps checks existing VIT risk scores and ratings. The test, all its steps, and its shared Script Include belong to **Vulnerability Response (`sn_vul`)**. All VR/USEM tests in this repository follow `CMPNY VR: <TEST NAME> - USEM`; see [repository conventions](../../AGENTS.md).

## Import v4 into your existing suite

1. Download the raw [XML update set](VR_Risk_Data_Health_ATF.update-set.xml) from GitHub (use **Download raw file**, not Save Page).
2. In a development/test instance with Vulnerability Response and ATF installed, open **System Update Sets > Retrieved Update Sets > Import Update Set from XML** and upload it.
3. Preview **CMPNY VR: Risk score and rating health - USEM - v4**, resolve preview problems, and commit. It contains seven customer updates: one Script Include, one test, and five steps including their input values. It references the existing `sn_vul` scope and OOB Run Server Side Script configuration; it does not create or overwrite those dependencies.
4. Select **Vulnerability Response** in the application picker. Open **System Definition > Script Includes > VRRiskDataHealth** with API name **`sn_vul.VRRiskDataHealth`** and review the single settings block at the top.
5. Add **CMPNY VR: Risk score and rating health - USEM** to your existing suite, then run it after imports and scoring finish.

**Upgrading from v3:** v4 keeps the same scoped test, step and helper IDs, preserving suite membership. It adds only the environment-specific mismatch policy and reporting; population variance, value checks and distribution checks are unchanged.

**Upgrading from v1/v2:** the scoped package (introduced in v3) creates a replacement with new record IDs, so it does not attempt to change the scope of your installed Global records. Replace the old **VR - Risk score and rating health** test in your suite with the new named test, and deactivate the old Global test. Copy any desired settings into the new `sn_vul` helper. The old Global helper is not used by the new test. This one-time replacement requires updating suite membership.

Reimporting the same scoped package replaces the helper's editable settings. Preserve your configured values first. Importing does not create a suite, enable ATF, run the test, or change VIT records. The XML follows the SDK's step-input replacement format, with cleanup restricted to inputs for the five packaged steps.

## All settings in one place

Edit **only `this.config` inside `initialize`**, between the **ALL TEST SETTINGS** and **END OF ALL EDITABLE TEST SETTINGS** banners in [VRRiskDataHealth.js](VRRiskDataHealth.js). All five steps call that helper; there are no duplicated settings in step scripts.

| Settings | Default / purpose |
| --- | --- |
| `configurationReviewed` | `false`; set `true` after reviewing the entire block |
| `table`, `scoreField`, `ratingField` | `sn_vul_vulnerable_item`, `risk_score`, `risk_rating` |
| `populationLabel`, `filters` | Active VITs; direct-field AND conditions using stored values |
| `minimumRecords` | **40,000,000**, inclusive, for both query counts |
| `maximumRecords` | **100,000,000**, inclusive, for both query counts |
| `populationCountTolerance.maxDifferencePercent` | **0.0125%** of the first count; `0` requires exact equality |
| `scoreMinimum`, `scoreMaximum` | Integer score domain 0–100 |
| `ratings` | Stored rating values, score bands and editable percentage ranges below |
| `mismatchTolerance.dev`, `mismatchTolerance.eng` | Exact `instanceName` defaults `DEV` / `ENG`; each `maxPercent` defaults to **0.00002%** of grouped VITs |
| `mismatchTolerance.test.instanceName` | `TEST`; Test and every unmatched instance always have **zero** mismatch allowance |
| `meanScore.min`, `meanScore.max` | Both `null` disables mean bounds; set both to enable |
| `outputDecimals` | `6`; display precision only, comparisons use unrounded values |

The minimum and maximum apply separately to the ungrouped population count and the grouped snapshot total. Count tolerance never extends these bounds. Exceeding 100 million fails; the script does not truncate the query to 100 million or sample records.

Count variance is **percentage-based only**: `floor(populationCount * maxDifferencePercent / 100)` is the allowed absolute difference in either direction. The default corresponds to **5,000 records at 40 million** and **12,500 at 100 million**. It is not a fixed 5,000-record cap. Accepted differences are shown; failures show both counts, the allowance and the excess in records. A count difference cannot establish its cause: concurrent updates or omitted groups can both produce a discrepancy.

### Environment-specific score/rating mismatch allowance

Steps 4 and 5 read `gs.getProperty('instance_name', '')`. Configure the exact instance property values in the central `mismatchTolerance` block; matching ignores case and surrounding whitespace, but never uses substrings. For example, if your Dev instance's property is `companydev`, replace `DEV` with `companydev`. Configured names must be nonempty and distinct. Output labels are **Dev**, **Eng** and **Test**; other or missing values show **Unmatched instance** and get zero allowance. A property lookup error fails the check.

Only Dev and Eng have editable `maxPercent` settings. Their allowed mismatch count is `floor(snapshot.total * maxPercent / 100)`, using the grouped population actually checked. **0.00002%** permits **8 at 40 million** and **20 at 100 million**; smaller fractional allowances round down, never up. Test and unmatched instances stay at zero. This allowance applies only to valid scores outside their stored rating's band. It never excuses missing/invalid values, population failures, count variance failures, distribution failures or mean-score failures.

The consistency result and, when executed, distribution result always show actual and allowed mismatch counts, the environment and Pass/Fail. The threshold is inclusive; exceeding it fails the step/test and reports the excess:

```text
Score/rating mismatches: 8 actual | allowed: 8 (0.00002% of 40000000 grouped VITs) | Environment: Dev | Pass | within allowance
Score/rating mismatches: 9 actual | allowed: 8 (0.00002% of 40000000 grouped VITs) | Environment: Eng | Fail | above allowance by 1 records
Score/rating mismatches: 1 actual | allowed: 0 (0% of 40000000 grouped VITs) | Environment: Test | Fail | above allowance by 1 records
```

### Editable sample percentage ranges

These are **illustrative starter values**, not measured enterprise data or ServiceNow recommendations. They already include room for variation; there is no additional fixed-record margin around rating bounds. For example, a hypothetical mix of 0.5% Critical, 2% High, 20% Medium, 72.5% Low and 5% None falls inside the ranges. No sample VITs are inserted.

| Rating | Stored value | Score band | Sample accepted share of VITs |
| --- | --- | --- | --- |
| Critical | `1` | 90–100 | 0.1–1.5% |
| High | `2` | 70–89 | 0.5–5% |
| Medium | `3` | 40–69 | 10–30% |
| Low | `4` | 1–39 | 55–85% |
| None | `5` | 0 | 0–10% |

Tune these ranges using verified healthy data for the same population. Review your instance's score/rating mapping too; the supplied score bands are the documented base mapping. Bands must cover the configured nonnegative integer domain without gaps or overlaps. Fractional scores are treated as invalid by this implementation. Blank scores/ratings are invalid, while a score of zero and a stored None rating are legitimate values.

Filters support direct fields and `=`, `!=`, `IN`, `NOT IN`, `>`, `>=`, `<`, `<=`. For one source, add `{ field: 'source', operator: '=', value: 'YOUR_STORED_SOURCE_VALUE' }` to the existing active filter and update the population label, bounds and percentage ranges for that source. Literal date filters are allowed; dot-walking, encoded queries and `javascript:` expressions are not. Score/rating fields cannot be filters because that would hide unhealthy data. A narrower population will likely need different minimum/maximum counts.

After review, set `configurationReviewed: true`. Invalid fields, invalid limits, incomplete ranges, impossible percentage bounds or partial mean bounds fail configuration. The review gate prevents the sample defaults being mistaken for an approved enterprise baseline.

## Five imported steps

All five are **Server > Run Server Side Script**, active, and in **Vulnerability Response**. The helper is active, server-only, not client callable, and accessible from its own scope only.

| Order | Check | Script | Pass condition |
| --- | --- | --- | --- |
| 1 | Configuration and fields | [01-configuration.js](steps/01-configuration.js) | Settings reviewed and schema/limits valid |
| 2 | Population bounds | [02-population.js](steps/02-population.js) | Both counts within min/max and difference within percentage tolerance |
| 3 | Score/rating values | [03-values.js](steps/03-values.js) | No missing, fractional/out-of-range scores or blank/unknown ratings |
| 4 | Score/rating consistency | [04-consistency.js](steps/04-consistency.js) | Valid score/rating mismatches do not exceed the environment allowance; population and value checks also pass |
| 5 | Rating distribution | [05-distribution.js](steps/05-distribution.js) | All five percentage ranges, enabled mean bounds and prerequisite checks pass |

The standard `assertEqual` assertion fails the step/test when a check fails. ATF normally stops at the first failing step; step 5 cannot print if an earlier step stops the test. **Whenever step 5 executes**, it prints all five ratings, even when some bounds or prerequisites fail. No custom step configuration or Jasmine suite is required.

## Step 5 output

Each rating has its **actual percentage**, **expected range**, **Pass/Fail**, count and any breach delta. Range status is specific to that rating's percentage; the overall step can still fail because the population is invalid or scores/ratings are inconsistent. Unknown ratings are included in the total denominator and reported separately as invalid, so known categories may add up to less than 100% in unhealthy data.

Example with a user-edited High range:

```text
High: 7.123123% | expected: 0.5-1.5% | Fail | above max by 5.623123 percentage points | count: 7123123/100000000
Low: 70.000000% | expected: 55-85% | Pass | within range | count: 70000000/100000000
```

The report also includes Critical, Medium and None. Deltas between percentages are **percentage points**, not relative percent changes. Tiny breaches that would round to zero are shown as less than the smallest displayed unit, such as `<0.000001 percentage points`. Empty populations or query/configuration errors print `unavailable` for every rating rather than inventing percentages. Mean score is informational unless both bounds are configured; enabled mean bounds also report deltas.

Percentages and the weighted mean use the **same grouped snapshot total**, even when the two counts differ within tolerance. The test never excludes invalid data merely to obtain a passing percentage. It does not independently verify the integration payload or calculator inputs; an incorrect distribution could still fit a wide accepted range.

## Execution and performance

Run in **sub-production** after integration and risk recalculation finish. Each data step reads the population again, so the test is not a transactionally frozen snapshot. Count checks cannot detect equal-count changes between queries. Reads are subject to the execution context's domain/query visibility; this is not an ACL test.

Database aggregation covers the whole filtered population. The four data steps issue eight aggregate queries rather than loading 40–100 million individual records into JavaScript. Assess runtime in your instance; the population maximum is an assertion, not a database scan limit. Errors fail the check rather than produce a healthy result.

## Sources and maintenance

- [ServiceNow ATF server steps](https://www.servicenow.com/docs/r/application-development/automated-test-framework-atf/test-steps-server-category.html) and [ATF execution](https://www.servicenow.com/docs/r/application-development/automated-test-framework-atf/atf-run-test.html).
- [VR calculators and score weights](https://www.servicenow.com/docs/r/security-management/vulnerability-response/vuln-calculators-rules.html).
- [GlideAggregate API](https://www.servicenow.com/docs/r/api-reference/server-api-reference/c_GlideAggregateAPI.html) and [GlideRecord API](https://www.servicenow.com/docs/r/xanadu/api-reference/server-api-reference/c_GlideRecordAPI.html).
- [Scoped GlideSystem API (`gs.getProperty`)](https://www.servicenow.com/docs/r/api-reference/server-api-reference/c_GlideSystemScopedAPI.html).
- [XML import](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_SaveAnUpdateSetAsAnXMLFile.html) and [preview](https://www.servicenow.com/docs/r/application-development/system-update-sets/t_PreviewARemoteUpdateSet.html).
- Official [SDK build plugins 4.13.0](https://www.npmjs.com/package/@servicenow/sdk-build-plugins/v/4.13.0), `src/atf/step-configs.ts` and `src/atf/test-plugin.ts`: OOB step/input IDs and serialization.
- [ServiceNow's published update-set example](https://github.com/ServiceNow/example-restclient-myworkapp-nodejs/blob/6e4b93759c45b1d33a2515e40af049f6b784d8f0/mywork_update_set/sys_remote_update_set_2f48a7d74f4652002fa02f1e0210c785.xml): XML envelope format.
- [ServiceNow employee's exported VR record](https://www.servicenow.com/community/app-engine-forum/helpers-translate-not-working/td-p/3323960): `sn_vul` scope/package reference `054cdcc2ff200200158bffffffffff94`. Confirm this dependency resolves during preview on your instance.

From this `atf-tests/vr-data-health` directory, rebuild the XML after editing source:

```sh
python3 tools/build_vr_atf_xml.py
python3 tools/build_vr_atf_xml.py --check
python3 tests/vr-atf-xml.test.py
node tests/vr-risk-data-health.test.js
```

Local tests use mocked ServiceNow APIs, including compressed aggregate fixtures for enterprise-sized populations. Live XML import, scoped execution and runtime validation are still required.
