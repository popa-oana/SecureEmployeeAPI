"""Safe HTTP errors using fictitious inputs and temporary fault injection."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient


INTERNAL_DETAILS = (
    "Traceback", "RuntimeError", "ResponseValidationError", "ValueError",
    "main.py", "security.py", "dependencies.py", ".env",
)


def assert_safe_error(response, expected_status, check_values, *extra_values):
    assert response.status_code == expected_status
    check_values(response.text, *extra_values)
    assert not any(value in response.text for value in INTERNAL_DETAILS)
    if expected_status != 500:
        assert set(response.json()) == {"detail"}
        assert response.json()["detail"]


@pytest.mark.parametrize("case", ["missing", "invalid", "expired"])
def test_401_token_errors_are_safe(
    client, protected_get_path, token_factory, assert_no_confidential_values, case
):
    token = "fictitious-invalid-jwt"
    if case == "expired":
        token = token_factory(expires_in=timedelta(minutes=-5))
    headers = {} if case == "missing" else {"Authorization": "Bearer " + token}
    response = client.get(protected_get_path, headers=headers)
    assert_safe_error(response, 401, assert_no_confidential_values, token)
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("username", ["employee_demo", "hr_reader", "hr_admin"])
def test_401_wrong_credentials_are_safe(client, assert_no_confidential_values, username):
    wrong_password = "fictitious-rejected-password-marker"
    response = client.post("/token", data={"username": username, "password": wrong_password})
    assert_safe_error(response, 401, assert_no_confidential_values, wrong_password)
    assert response.json() == {"detail": "Incorrect username or password"}


@pytest.mark.parametrize("case", ["scope", "role", "other_employee"])
def test_403_does_not_reveal_secrets_or_resource_existence(
    client, auth_headers, token_factory, employee_records, monkeypatch,
    assert_no_confidential_values, case
):
    employee_id = employee_records["own"]["id"]
    suffix = ""
    if case == "scope":
        headers = {"Authorization": "Bearer " + token_factory(scopes=[])}
    elif case == "role":
        from app.users import USERS

        monkeypatch.setitem(USERS["hr_reader"], "scopes", ["employees:read", "employees:sensitive"])
        headers = auth_headers("hr_reader")
        suffix = "/sensitive"
    else:
        headers = auth_headers("employee_demo")
        employee_id = employee_records["other"]["id"]
    missing_id = max(record["id"] for record in employee_records.values()) + 100
    existing = client.get(f"/employees/{employee_id}{suffix}", headers=headers)
    missing = client.get(f"/employees/{missing_id}{suffix}", headers=headers)
    token = headers["Authorization"].removeprefix("Bearer ")
    for response in (existing, missing):
        assert_safe_error(response, 403, assert_no_confidential_values, token)
    assert missing.json() == existing.json()


@pytest.mark.parametrize("operation", ["public", "sensitive", "update", "delete"])
def test_404_is_generic_for_authorized_user(
    client, auth_headers, employee_records, assert_no_confidential_values, operation
):
    missing_id = max(record["id"] for record in employee_records.values()) + 100
    path = f"/employees/{missing_id}"
    method, options = "GET", {"headers": auth_headers("hr_admin")}
    if operation == "sensitive":
        path += "/sensitive"
    elif operation == "update":
        method = "PUT"
        options["json"] = {k: v for k, v in employee_records["own"].items() if k != "id"}
    elif operation == "delete":
        method = "DELETE"
    response = client.request(method, path, **options)
    assert_safe_error(response, 404, assert_no_confidential_values)
    assert response.json() == {"detail": "Employee not found"}


@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize(
    "case", ["phone_length", "salary_format", "missing_fields", "invalid_json", "wrong_types", "whole_list"]
)
def test_422_keeps_useful_details_without_rejected_input(
    client, auth_headers, employee_records, test_environment,
    assert_no_confidential_values, method, case
):
    record = employee_records["own"]
    payload = {k: v for k, v in record.items() if k != "id"}
    headers = auth_headers("hr_admin")
    token = headers["Authorization"].removeprefix("Bearer ")
    marker = "FICTIONAL_REJECTED_VALUE_MARKER_TOO_LONG_FOR_PHONE"
    expected_field = None
    if case == "phone_length":
        payload["phone"] = marker
        expected_field = "phone"
    elif case == "salary_format":
        payload["salary"] = marker
        expected_field = "salary"
    elif case == "missing_fields":
        # Missing required fields used to echo this entire object in 'input'.
        payload = {"phone": record["phone"], "salary": record["salary"],
                   "password": test_environment["passwords"]["hr_admin"], "token": token}
        expected_field = "full_name"
    elif case == "wrong_types":
        payload["phone"] = {"password": test_environment["passwords"]["hr_admin"], "token": token}
        payload["salary"] = [marker]
        expected_field = "phone"
    elif case == "whole_list":
        payload = [payload, {"token": token, "key": test_environment["jwt_key"]}]

    path = "/employees" if method == "POST" else f"/employees/{record['id']}"
    if case == "invalid_json":
        response = client.request(
            method, path, headers={**headers, "Content-Type": "application/json"},
            content='{"phone":"' + marker + '","salary": INVALID_JSON}',
        )
    else:
        response = client.request(method, path, headers=headers, json=payload)
    assert_safe_error(response, 422, assert_no_confidential_values, marker, token)
    errors = response.json()["detail"]
    assert isinstance(errors, list) and errors
    for error in errors:
        assert set(error) == {"loc", "msg", "type"}
        assert isinstance(error["loc"], list) and error["loc"][0] == "body"
        assert isinstance(error["msg"], str) and error["msg"]
        assert isinstance(error["type"], str) and error["type"]
    if expected_field:
        assert any(error["loc"] == ["body", expected_field] for error in errors)
    if case == "phone_length":
        assert any("30" in error["msg"] for error in errors)


@pytest.mark.parametrize("suffix", ["", "/sensitive"], ids=["public", "sensitive"])
def test_422_path_error_does_not_echo_value(
    client, auth_headers, assert_no_confidential_values, suffix
):
    marker = "FICTIONAL_PATH_SECRET_MARKER"
    response = client.get(f"/employees/{marker}{suffix}", headers=auth_headers("hr_admin"))
    assert_safe_error(response, 422, assert_no_confidential_values, marker)
    for error in response.json()["detail"]:
        assert set(error) == {"loc", "msg", "type"}
        assert error["loc"] == ["path", "employee_id"]


@pytest.mark.parametrize("failure", ["login", "storage", "response_validation"])
def test_500_hides_internal_exception_and_recovers(
    application, client, auth_headers, employee_records, test_environment,
    assert_no_confidential_values, monkeypatch, failure
):
    from app import main
    from app.data import EMPLOYEES

    headers = auth_headers("hr_admin")
    token = headers["Authorization"].removeprefix("Bearer ")
    marker = "FICTIONAL_INTERNAL_EXCEPTION_MARKER"
    internal_message = f"{marker}: main.py {test_environment['jwt_key']} {token}"
    own_id = employee_records["own"]["id"]

    def fail_login(*args, **kwargs):
        raise RuntimeError(internal_message)

    class FailingStore(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError(internal_message)

    # Revert injected faults before checking that normal requests recover.
    with monkeypatch.context() as fault:
        if failure == "login":
            fault.setattr(main, "authenticate_user", fail_login)
        elif failure == "storage":
            fault.setattr(main, "EMPLOYEES", FailingStore(EMPLOYEES))
        else:
            fault.setitem(EMPLOYEES, own_id, {**EMPLOYEES[own_id], "position": {"internal": internal_message}})
        with TestClient(application, raise_server_exceptions=False) as error_client:
            if failure == "login":
                response = error_client.post(
                    "/token", data={"username": "hr_admin", "password": test_environment["passwords"]["hr_admin"]}
                )
            else:
                suffix = "/sensitive" if failure == "storage" else ""
                response = error_client.get(f"/employees/{own_id}{suffix}", headers=headers)
        assert_safe_error(response, 500, assert_no_confidential_values, marker, token)
        assert response.text == "Internal Server Error"

    recovered_login = client.post(
        "/token", data={"username": "hr_admin", "password": test_environment["passwords"]["hr_admin"]}
    )
    assert recovered_login.status_code == 200
    assert client.get(f"/employees/{own_id}", headers=headers).status_code == 200
