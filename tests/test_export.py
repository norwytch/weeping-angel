import json

from weeping_angel.detector import Finding
from weeping_angel.export import ecs_event, ocsf_finding, to_jsonl


def finding(severity="high", rule="R1_si_fn_birth_divergence", file_id="evil.exe"):
    return Finding(file_id, rule, severity, "creation predates the MFT birth", ())


def test_ecs_has_core_fields_and_attack_mapping():
    doc = ecs_event(finding(), timestamp=1_700_000_000.0, host="host-7")
    assert doc["event"]["kind"] == "alert"
    assert doc["rule"]["id"] == "R1_si_fn_birth_divergence"
    assert doc["file"]["name"] == "evil.exe"
    assert doc["threat"]["technique"]["id"] == "T1070.006"
    assert doc["threat"]["tactic"]["id"] == "TA0005"
    assert doc["@timestamp"].startswith("2023-11-14T")
    assert doc["host"]["name"] == "host-7"


def test_ecs_severity_maps():
    assert ecs_event(finding("high"))["event"]["severity"] == 73
    assert ecs_event(finding("medium"))["event"]["severity"] == 47


def test_ecs_omits_optional_fields_when_absent():
    doc = ecs_event(finding())
    assert "@timestamp" not in doc
    assert "host" not in doc


def test_ocsf_is_a_detection_finding():
    doc = ocsf_finding(finding(), timestamp=1_700_000_000.0)
    assert doc["class_uid"] == 2004
    assert doc["category_uid"] == 2
    assert doc["type_uid"] == 200401
    assert doc["severity_id"] == 4  # high
    assert doc["attacks"][0]["technique"]["uid"] == "T1070.006"
    assert doc["attacks"][0]["tactic"]["uid"] == "TA0005"
    assert doc["evidences"][0]["file"]["path"] == "evil.exe"
    assert doc["time"] == 1_700_000_000_000  # epoch ms


def test_ocsf_severity_id_for_medium():
    assert ocsf_finding(finding("medium"))["severity_id"] == 3


def test_to_jsonl_emits_one_valid_json_object_per_finding():
    findings = [finding("high"), finding("medium", rule="R6_subsecond_truncation")]
    out = to_jsonl(findings, schema="ocsf")
    lines = out.splitlines()
    assert len(lines) == 2
    for line in lines:
        assert json.loads(line)["class_uid"] == 2004


def test_unknown_schema_rejected():
    try:
        to_jsonl([finding()], schema="splunk")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown schema")
