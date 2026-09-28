# VR / USEM test conventions

- Name every VR/USEM ATF test `CMPNY VR: <TEST NAME> - USEM`.
- Put VR tests, their steps and their Script Includes in Vulnerability Response (`sn_vul`), not Global. Do not overwrite the installed scope or OOB ATF step configuration.
- Keep all editable runtime settings in one clearly marked block near the top of the shared Script Include; step scripts should not duplicate settings.
- Default risk-health population bounds to 40,000,000–100,000,000 records, inclusive.
- Express population count tolerance as a percentage. The current default, 0.0125%, corresponds to 5,000 records at 40 million; do not retain an additional fixed-record allowance.
- Provide clearly labeled illustrative rating percentage ranges that can be edited; do not present samples as an enterprise baseline.
- When the distribution step executes, report every rating's actual percentage, expected range, Pass/Fail, and distance below/above a breached boundary in percentage points. If data cannot be obtained, report unavailable instead of fabricating percentages.
- Deliver an XML update set alongside source. Rebuild and verify it when source changes. Use new scoped record IDs when replacing the legacy Global version and document the suite replacement.
