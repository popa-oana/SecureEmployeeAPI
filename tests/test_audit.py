"""Audit successes through the API, including the actual console serialization."""

import io
import json
import logging
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest


OPERATIONS = [
    pytest.param("POST", "employee.create", 201, id="create"),
    pytest.param("PUT", "employee.update", 200, id="update"),
    pytest.param("DELETE", "employee.delete", 204, id="delete"),
    pytest.param("GET", "employee.read_sensitive", 200, id="read-sensitive"),
]


class RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def audit_capture(application):
    from app.audit import logger

    original_level, original_propagate = logger.level, logger.propagate
    streams = [
        (handler, handler.stream)
        for handler in logger.handlers
        # Capture the application's console handler, not pytest's subclasses.
        if type(handler) is logging.StreamHandler
    ]
    assert streams, "Audit needs a terminal handler"
    assert not any(isinstance(handler, RecordingHandler) for handler in logger.handlers)
    recorder = RecordingHandler()
    output = io.StringIO()
    try:
        for handler, _ in streams:
            handler.setStream(output)
        # Attach directly; no dependency on propagation or pytest's own handlers.
        logger.addHandler(recorder)
        yield SimpleNamespace(output=output, records=recorder.records)
    finally:
        logger.removeHandler(recorder)
        recorder.close()
        for handler, stream in streams:
            handler.setStream(stream)
            assert handler in logger.handlers and handler.stream is stream
        assert recorder not in logger.handlers
        assert (logger.level, logger.propagate) == (original_level, original_propagate)
        output.close()


@pytest.fixture
def audit_payload(employee_records):
    return {key: value for key, value in employee_records["own"].items() if key != "id"}


def audited_request(client, method, employee_id, headers, payload):
    if method == "POST":
        return client.post("/employees", headers=headers, json=payload)
    path = f"/employees/{employee_id}"
    if method == "GET":
        path += "/sensitive"
    options = {"headers": headers}
    if method == "PUT":
        options["json"] = payload
    return client.request(method, path, **options)


@pytest.mark.parametrize("method, operation, expected_status", OPERATIONS)
def test_success_emits_one_safe_json_event(
    client, auth_headers, employee_records, audit_payload, audit_capture,
    assert_no_confidential_values, method, operation, expected_status
):
    headers = auth_headers("hr_admin")
    employee_id = employee_records["own"]["id"]
    started = datetime.now(timezone.utc)
    response = audited_request(client, method, employee_id, headers, audit_payload)
    finished = datetime.now(timezone.utc)
    assert response.status_code == expected_status
    if method == "POST":
        employee_id = response.json()["id"]

    lines = audit_capture.output.getvalue().splitlines()
    assert len(lines) == 1
    assert len(audit_capture.records) == 1
    event = json.loads(lines[0])
    assert json.loads(audit_capture.records[0].getMessage()) == event
    assert set(event) == {"timestamp", "actor", "operation", "employee_id", "result"}
    assert event["actor"] == "hr_admin"
    assert event["operation"] == operation
    assert event["employee_id"] == employee_id
    assert event["result"] == "success"
    timestamp = datetime.fromisoformat(event["timestamp"])
    assert timestamp.utcoffset() == timedelta(0)
    assert started <= timestamp <= finished
    token = headers["Authorization"].removeprefix("Bearer ")
    assert_no_confidential_values(lines[0], token)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "GET"])
@pytest.mark.parametrize(
    "case, expected_status",
    [("no_token", 401), ("invalid_token", 401), ("employee_demo", 403),
     ("hr_reader", 403), ("no_scope", 403), ("wrong_role", 403)],
)
def test_denied_request_emits_no_success(
    client, auth_headers, token_factory, employee_records, audit_payload,
    audit_capture, monkeypatch, method, case, expected_status
):
    from app.data import EMPLOYEES
    from app.users import USERS

    if case == "no_token":
        headers = {}
    elif case == "invalid_token":
        headers = {"Authorization": "Bearer fictitious-invalid-token"}
    elif case == "no_scope":
        headers = {"Authorization": "Bearer " + token_factory(scopes=[])}
    elif case == "wrong_role":
        monkeypatch.setitem(
            USERS["hr_reader"], "scopes",
            ["employees:read", "employees:write", "employees:sensitive"],
        )
        headers = auth_headers("hr_reader")
    else:
        headers = auth_headers(case)
    before = deepcopy(EMPLOYEES)
    response = audited_request(
        client, method, employee_records["own"]["id"], headers, audit_payload
    )
    assert response.status_code == expected_status
    assert audit_capture.records == []
    assert audit_capture.output.getvalue() == ""
    assert EMPLOYEES == before


@pytest.mark.parametrize("method", ["PUT", "DELETE", "GET"])
def test_missing_resource_emits_no_success(
    client, auth_headers, employee_records, audit_payload, audit_capture, method
):
    missing_id = max(record["id"] for record in employee_records.values()) + 100
    response = audited_request(
        client, method, missing_id, auth_headers("hr_admin"), audit_payload
    )
    assert response.status_code == 404
    assert audit_capture.records == []
    assert audit_capture.output.getvalue() == ""


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_invalid_input_emits_no_success(
    client, auth_headers, employee_records, audit_payload, audit_capture, method
):
    response = audited_request(
        client, method, employee_records["own"]["id"], auth_headers("hr_admin"),
        {**audit_payload, "salary": "fictitious-invalid-salary"},
    )
    assert response.status_code == 422
    assert audit_capture.records == []
    assert audit_capture.output.getvalue() == ""
