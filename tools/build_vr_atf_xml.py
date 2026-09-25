"""Build the importable update set from reviewed JavaScript, using only stdlib.

ATF record/input layout and OOB IDs: @servicenow/sdk-build-plugins 4.13.0,
src/atf/test-plugin.ts and src/atf/step-configs.ts (official ServiceNow npm).
The package contains seven customer updates, not a suite or execution settings.
"""

from hashlib import sha256
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ATF = ROOT / "Scripts" / "ATF"
OUTPUT = ATF / "VR_Risk_Data_Health_ATF.update-set.xml"
NAME = "VR - Risk score and rating health"
STAMP = "2026-09-25 19:02:37"
PACKAGE_REVISION = "v2"  # New envelope IDs; test/helper/step IDs stay stable.
STEP_CONFIG = "41de4a935332120028bc29cac2dc349a"
JASMINE_INPUT = "42f2564b73031300440211d8faf6a777"
SCRIPT_INPUT = "989d9e235324220002c6435723dc3484"
STEPS = [
    ("configuration", "Configuration and fields"),
    ("population", "Population size"),
    ("values", "Score and rating values"),
    ("consistency", "Score/rating consistency"),
    ("distribution", "Rating distribution"),
]


def guid(name):
    """Stable IDs make rebuilding/reimporting update the same owned artifacts."""
    return sha256(("petroskyluke/servicenow-health-check/vr-atf/v1/" + name).encode()).hexdigest()[:32]


def field(parent, name, value="", **attributes):
    child = ET.SubElement(parent, name, attributes)
    child.text = str(value)
    return child


def metadata(record, table, identity, name):
    for key, value in {
        "sys_id": identity,
        "sys_class_name": table,
        "sys_name": name,
        "sys_update_name": table + "_" + identity,
        "sys_customer_update": "true",
        "sys_replace_on_upgrade": "false",
        "sys_mod_count": "0",
        "sys_created_by": "repository",
        "sys_updated_by": "repository",
        "sys_created_on": STAMP,
        "sys_updated_on": STAMP,
    }.items():
        field(record, key, value)
    field(record, "sys_scope", "global", display_value="Global")
    field(record, "sys_package", "global", display_value="Global", source="global")


def payload(table, identity, name, values):
    root = ET.Element("record_update", {"table": table})
    record = ET.SubElement(root, table, {"action": "INSERT_OR_UPDATE", "apply_defaults": "true"})
    metadata(record, table, identity, name)
    for key, value in values.items():
        field(record, key, value)
    return root


def build():
    root = ET.Element("unload", {"unload_date": STAMP})
    remote_id = guid(PACKAGE_REVISION + "/remote-update-set")
    remote = ET.SubElement(root, "sys_remote_update_set", {"action": "INSERT_OR_UPDATE"})
    for key, value in {
        "sys_id": remote_id,
        "name": NAME + " - " + PACKAGE_REVISION,
        "description": "One Global ATF test, five Run Server Side Script steps and VRRiskDataHealth. Configure percentage ranges before running; add to an existing suite. Reads VIT data only.",
        "application": "global",
        "application_name": "Global",
        "application_scope": "global",
        "remote_sys_id": guid(PACKAGE_REVISION + "/source-update-set"),
        "state": "loaded",
        "sys_created_by": "repository",
        "sys_updated_by": "repository",
        "sys_created_on": STAMP,
        "sys_updated_on": STAMP,
        "sys_mod_count": "0",
    }.items():
        field(remote, key, value)

    def customer_update(table, identity, display, type_name, contents):
        update = ET.SubElement(root, "sys_update_xml", {"action": "INSERT_OR_UPDATE"})
        for key, value in {
            "sys_id": guid(PACKAGE_REVISION + "/update/" + identity),
            "action": "INSERT_OR_UPDATE",
            "application": "global",
            "category": "customer",
            "name": table + "_" + identity,
            # Escaped XML preserves JavaScript through both parse layers.
            "payload": '<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(contents, encoding="unicode"),
            "remote_update_set": remote_id,
            "replace_on_upgrade": "false",
            "target_name": display,
            "type": type_name,
            "update_domain": "global",
            "sys_created_by": "repository",
            "sys_updated_by": "repository",
            "sys_created_on": STAMP,
            "sys_updated_on": STAMP,
            "sys_mod_count": "0",
        }.items():
            field(update, key, value)

    include_id = guid("script-include")
    helper = payload("sys_script_include", include_id, "VRRiskDataHealth", {
        "name": "VRRiskDataHealth",
        "api_name": "global.VRRiskDataHealth",
        "active": "true",
        "access": "package_private",
        "client_callable": "false",
        "description": "Read-only VIT risk score/rating ATF health checks. Edit configuration in initialize before running.",
        "script": (ATF / "VRRiskDataHealth.js").read_text(),
    })
    customer_update("sys_script_include", include_id, "VRRiskDataHealth", "Script Include", helper)

    test_id = guid("test")
    test = payload("sys_atf_test", test_id, NAME, {
        "name": NAME,
        "active": "true",
        "description": "Read-only health checks for existing VIT risk scores and ratings. Configure VRRiskDataHealth before running after imports and recalculation finish. Add this test to your existing suite.",
        "enable_parameterized_testing": "false",
        "fail_on_server_error": "true",
    })
    customer_update("sys_atf_test", test_id, NAME, "Test", test)

    for order, (check, label) in enumerate(STEPS, 1):
        step_id = guid("step/" + check)
        step = payload("sys_atf_step", step_id, label, {
            "active": "true",
            "description": label,
            "display_name": "Run Server Side Script",
            "notes": label + " - uses the shared VRRiskDataHealth configuration.",
            "order": order,
            "step_config": STEP_CONFIG,
            "test": test_id,
        })
        # Official SDK serializer replaces variable values for THIS step only.
        ET.SubElement(step, "sys_variable_value", {
            "action": "delete_multiple", "query": "document_key=" + step_id,
        })
        script = (ATF / "steps" / f"{order:02}-{check}.js").read_text()
        for variable_order, key, variable_id, value in [
            (100, "jasmine_version", JASMINE_INPUT, "3.1"),
            (200, "script", SCRIPT_INPUT, script),
        ]:
            variable = ET.SubElement(step, "sys_variable_value", {
                "action": "INSERT_OR_UPDATE", "apply_defaults": "true",
            })
            for name, text in {
                "sys_id": guid("input/" + check + "/" + key),
                "document": "sys_atf_step",
                "document_key": step_id,
                "variable": variable_id,
                "value": value,
                "order": variable_order,
            }.items():
                field(variable, name, text)
        customer_update("sys_atf_step", step_id, label, "Test Step", step)

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


if __name__ == "__main__":
    result = build()
    if sys.argv[1:] == ["--check"]:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit("XML is stale. Run python3 tools/build_vr_atf_xml.py")
        print("Passed: XML matches the current helper and all five step scripts.")
    elif not sys.argv[1:]:
        OUTPUT.write_text(result)
        print("Built " + str(OUTPUT))
    else:
        raise SystemExit("Usage: python3 tools/build_vr_atf_xml.py [--check]")
