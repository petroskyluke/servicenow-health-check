# ServiceNow tools

Scripts and Automated Test Framework (ATF) tests for ServiceNow.

| Tool | Files and instructions |
| --- | --- |
| Application health check | [Guide](health-check/README.md) · [Script](health-check/scripts/USEM_HC_ApplicationHealthScan.js) |
| VR risk score and rating data health ATF test | [Guide](atf-tests/vr-data-health/README.md) · [Importable XML](atf-tests/vr-data-health/VR_Risk_Data_Health_ATF.update-set.xml) |

## Repository layout

```text
health-check/
  README.md
  scripts/                      Application health-check scripts
  tests/                        Local scan regression tests
atf-tests/
  vr-data-health/
    README.md                   Import and configuration instructions
    VRRiskDataHealth.js         Shared Script Include and all test settings
    VR_Risk_Data_Health_ATF.update-set.xml
    steps/                      Five ATF step scripts
    tools/                      XML build tool
    tests/                      Local JavaScript and XML tests
```

Each ATF test has its own folder containing its importable XML and associated source, steps, documentation, build tools and tests. See [VR / USEM conventions](AGENTS.md) when adding tests.

## Local validation

Run from the repository root:

```sh
node --check health-check/scripts/USEM_HC_ApplicationHealthScan.js
node health-check/tests/application-health-scan.test.js
python3 atf-tests/vr-data-health/tools/build_vr_atf_xml.py --check
python3 atf-tests/vr-data-health/tests/vr-atf-xml.test.py
node atf-tests/vr-data-health/tests/vr-risk-data-health.test.js
```

To rebuild the ATF XML after a source change:

```sh
python3 atf-tests/vr-data-health/tools/build_vr_atf_xml.py
```

Local tests use mocked ServiceNow APIs. Live instance import and execution validation are still required.
