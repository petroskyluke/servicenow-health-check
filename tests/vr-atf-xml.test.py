"""Check the actual distributable update set, including its nested payloads.

No ServiceNow instance or third-party dependencies are used. OOB input IDs are
independently pinned to the official ServiceNow SDK build plugins 4.13.0.
"""

from collections import Counter
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
ATF = ROOT / "Scripts" / "ATF"
XML_FILE = ATF / "VR_Risk_Data_Health_ATF.update-set.xml"
STEP_CONFIG_ID = "41de4a935332120028bc29cac2dc349a"
SCRIPT_VARIABLE_ID = "989d9e235324220002c6435723dc3484"
JASMINE_VARIABLE_ID = "42f2564b73031300440211d8faf6a777"
CHECKS = ("configuration", "population", "values", "consistency", "distribution")


class ATFXMLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = ET.parse(XML_FILE).getroot()
        cls.updates = cls.root.findall("sys_update_xml")
        # Parsing both layers also proves nested JavaScript XML escaping works.
        cls.payloads = [ET.fromstring(update.findtext("payload")) for update in cls.updates]

    def records(self, table):
        return [record for payload in self.payloads for record in payload.findall(table)]

    def test_seven_customer_updates_and_no_suite_or_business_data(self):
        self.assertEqual(self.root.tag, "unload")
        self.assertEqual(Counter(child.tag for child in self.root), {
            "sys_remote_update_set": 1, "sys_update_xml": 7,
        })
        self.assertEqual(Counter(payload.get("table") for payload in self.payloads), {
            "sys_script_include": 1, "sys_atf_test": 1, "sys_atf_step": 5,
        })
        remote = self.root.find("sys_remote_update_set")
        self.assertEqual(remote.get("action"), "INSERT_OR_UPDATE")
        self.assertEqual(remote.findtext("state"), "loaded")
        self.assertEqual(remote.findtext("application"), "global")
        for update, payload in zip(self.updates, self.payloads):
            self.assertEqual(update.get("action"), "INSERT_OR_UPDATE")
            self.assertEqual(update.findtext("action"), "INSERT_OR_UPDATE")
            self.assertEqual(update.findtext("category"), "customer")
            self.assertEqual(update.findtext("application"), "global")
            self.assertEqual(update.findtext("remote_update_set"), remote.findtext("sys_id"))
            self.assertEqual(payload.tag, "record_update")
            table = payload.get("table")
            expected = {table: 1, "sys_variable_value": 3} if table == "sys_atf_step" else {table: 1}
            self.assertEqual(Counter(record.tag for record in payload), expected)
            record = payload.find(table)
            self.assertEqual(update.findtext("name"), table + "_" + record.findtext("sys_id"))

    def test_all_metadata_and_steps_are_active_global_records(self):
        for payload in self.payloads:
            table = payload.get("table")
            record = payload.find(table)
            self.assertEqual(record.get("action"), "INSERT_OR_UPDATE")
            self.assertEqual(record.get("apply_defaults"), "true")
            self.assertEqual(record.findtext("sys_scope"), "global")
            self.assertEqual(record.findtext("sys_package"), "global")
            self.assertEqual(record.findtext("sys_class_name"), table)
            self.assertEqual(record.findtext("active"), "true")
            self.assertEqual(record.findtext("sys_update_name"), table + "_" + record.findtext("sys_id"))
        test = self.records("sys_atf_test")[0]
        self.assertEqual(test.findtext("name"), "VR - Risk score and rating health")
        self.assertEqual(test.findtext("fail_on_server_error"), "true")
        self.assertEqual(test.findtext("enable_parameterized_testing"), "false")

    def test_script_include_is_server_only_and_matches_reviewed_source(self):
        record = self.records("sys_script_include")[0]
        self.assertEqual(record.findtext("name"), "VRRiskDataHealth")
        self.assertEqual(record.findtext("api_name"), "global.VRRiskDataHealth")
        self.assertEqual(record.findtext("client_callable"), "false")
        self.assertEqual(record.findtext("access"), "package_private")
        source = (ATF / "VRRiskDataHealth.js").read_text(encoding="utf-8")
        self.assertEqual(record.findtext("script"), source)
        self.assertIn("configurationReviewed: false", source)
        self.assertEqual(source.count("minPercent: null, maxPercent: null"), 5)
        # Supplemental static guard; behavior tests cover the mock API boundary.
        self.assertIsNone(re.search(r"\.(?:insert|update|updateMultiple|deleteRecord|deleteMultiple)\s*\(", source))

    def test_five_steps_have_correct_inputs_sources_and_test_reference(self):
        test_id = self.records("sys_atf_test")[0].findtext("sys_id")
        step_payloads = sorted(
            (payload for payload in self.payloads if payload.get("table") == "sys_atf_step"),
            key=lambda payload: int(payload.findtext("sys_atf_step/order")),
        )
        for order, (check, payload) in enumerate(zip(CHECKS, step_payloads), 1):
            step = payload.find("sys_atf_step")
            step_id = step.findtext("sys_id")
            self.assertEqual(step.findtext("order"), str(order))
            self.assertEqual(step.findtext("test"), test_id)
            self.assertEqual(step.findtext("step_config"), STEP_CONFIG_ID)
            self.assertEqual(step.findtext("display_name"), "Run Server Side Script")
            values = [record for record in payload.findall("sys_variable_value")
                      if record.get("action") == "INSERT_OR_UPDATE"]
            self.assertEqual(len(values), 2)
            by_variable = {record.findtext("variable"): record for record in values}
            self.assertEqual(set(by_variable), {SCRIPT_VARIABLE_ID, JASMINE_VARIABLE_ID})
            for record in values:
                self.assertEqual(record.get("apply_defaults"), "true")
                self.assertEqual(record.findtext("document"), "sys_atf_step")
                self.assertEqual(record.findtext("document_key"), step_id)
            self.assertEqual(by_variable[JASMINE_VARIABLE_ID].findtext("order"), "100")
            self.assertEqual(by_variable[JASMINE_VARIABLE_ID].findtext("value"), "3.1")
            self.assertEqual(by_variable[SCRIPT_VARIABLE_ID].findtext("order"), "200")
            source = (ATF / "steps" / f"{order:02}-{check}.js").read_text(encoding="utf-8")
            self.assertEqual(by_variable[SCRIPT_VARIABLE_ID].findtext("value"), source)
            self.assertIn(".run('" + check + "')", source)
            self.assertIn("assertEqual", source)
        self.assertEqual(len(self.records("sys_variable_value")), 15)  # 10 inputs + 5 scoped cleanup actions

    def test_cleanup_is_limited_to_each_packaged_step(self):
        cleanup_count = 0
        for payload in self.payloads:
            for record in payload:
                if record.get("action") == "delete_multiple":
                    cleanup_count += 1
                    self.assertEqual(payload.get("table"), "sys_atf_step")
                    self.assertEqual(record.tag, "sys_variable_value")
                    step_id = payload.findtext("sys_atf_step/sys_id")
                    self.assertEqual(record.get("query"), "document_key=" + step_id)
                    self.assertEqual(set(record.attrib), {"action", "query"})
                    self.assertEqual(len(record), 0)
                else:
                    self.assertEqual(record.get("action"), "INSERT_OR_UPDATE")
        self.assertEqual(cleanup_count, 5)

    def test_created_record_ids_are_valid_unique_and_not_oob_dependency_ids(self):
        records = list(self.root)
        records += [record for payload in self.payloads for record in payload
                    if record.get("action") != "delete_multiple"]
        identities = [record.findtext("sys_id") for record in records]
        self.assertEqual(len(identities), 25)  # remote + 7 updates + 7 metadata + 10 inputs
        self.assertEqual(len(set(identities)), len(identities))
        for identity in identities:
            self.assertRegex(identity or "", r"^[0-9a-f]{32}$")
            self.assertNotIn(identity, {STEP_CONFIG_ID, SCRIPT_VARIABLE_ID, JASMINE_VARIABLE_ID})


if __name__ == "__main__":
    unittest.main(verbosity=2)
