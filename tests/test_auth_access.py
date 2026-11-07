"""JWT authentication and GET access control, tested through the HTTP API."""

from datetime import timedelta

import pytest


ACCOUNTS = ("employee_demo", "hr_reader", "hr_admin")
HR_ACCOUNTS = ("hr_reader", "hr_admin")
PUBLIC_FIELDS = {"id", "full_name", "department", "position"}


@pytest.mark.parametrize("username", ACCOUNTS)
def test_login_returns_usable_bearer_token(client, login, employee_records, username):
    token = login(username)
    assert token["token_type"] == "bearer"
    assert isinstance(token["access_token"], str) and token["access_token"]
    own_id = employee_records["own"]["id"]
    response = client.get(
        f"/employees/{own_id}",
        headers={"Authorization": "Bearer " + token["access_token"]},
    )
    assert response.status_code == 200
    assert response.json()["id"] == own_id


@pytest.mark.parametrize("username", ACCOUNTS)
def test_wrong_password_is_rejected(client, username):
    response = client.post(
        "/token", data={"username": username, "password": "fictitious-wrong-password"}
    )
    assert response.status_code == 401


def test_unknown_user_is_rejected(client):
    response = client.post(
        "/token",
        data={"username": "nonexistent-test-user", "password": "fictitious-password"},
    )
    assert response.status_code == 401


def test_missing_token_is_rejected(client, protected_get_path):
    assert client.get(protected_get_path).status_code == 401


@pytest.mark.parametrize("invalid_kind", ["malformed", "wrong_signature"])
def test_invalid_token_is_rejected(
    client, protected_get_path, token_factory, invalid_kind
):
    token = (
        "not-a-jwt"
        if invalid_kind == "malformed"
        else token_factory(key="fictitious-wrong-signing-key-at-least-32-characters")
    )
    response = client.get(
        protected_get_path, headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 401


def test_expired_token_is_rejected(client, protected_get_path, token_factory):
    token = token_factory(expires_in=timedelta(minutes=-5))
    response = client.get(
        protected_get_path, headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 401


def test_token_for_unknown_user_is_rejected(
    client, protected_get_path, token_factory
):
    token = token_factory(subject="nonexistent-test-user")
    response = client.get(
        protected_get_path, headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 401


def test_employee_can_read_only_own_public_record(client, auth_headers, employee_records):
    own = employee_records["own"]
    response = client.get(
        f"/employees/{own['id']}", headers=auth_headers("employee_demo")
    )
    assert response.status_code == 200
    assert response.json() == {key: own[key] for key in PUBLIC_FIELDS}
    assert "salary" not in response.json()
    assert "phone" not in response.json()


def test_employee_cannot_read_another_record(client, auth_headers, employee_records):
    other_id = employee_records["other"]["id"]
    response = client.get(
        f"/employees/{other_id}", headers=auth_headers("employee_demo")
    )
    assert response.status_code == 403


def test_employee_cannot_list_employees(client, auth_headers):
    response = client.get("/employees", headers=auth_headers("employee_demo"))
    assert response.status_code == 403


@pytest.mark.parametrize("username", HR_ACCOUNTS)
def test_hr_can_list_public_records(client, auth_headers, employee_records, username):
    response = client.get("/employees", headers=auth_headers(username))
    assert response.status_code == 200
    records = response.json()
    expected = [
        {key: record[key] for key in PUBLIC_FIELDS}
        for record in employee_records.values()
    ]
    assert sorted(records, key=lambda row: row["id"]) == sorted(
        expected, key=lambda row: row["id"]
    )
    assert all("salary" not in row and "phone" not in row for row in records)


@pytest.mark.parametrize("username", HR_ACCOUNTS)
@pytest.mark.parametrize("record_name", ["own", "other"])
def test_hr_can_read_any_public_record(
    client, auth_headers, employee_records, username, record_name
):
    record = employee_records[record_name]
    response = client.get(
        f"/employees/{record['id']}", headers=auth_headers(username)
    )
    assert response.status_code == 200
    assert response.json() == {key: record[key] for key in PUBLIC_FIELDS}
    assert "salary" not in response.json()
    assert "phone" not in response.json()


@pytest.mark.parametrize("username", ACCOUNTS)
def test_valid_token_without_read_scope_is_forbidden(
    client, token_factory, employee_records, username
):
    token = token_factory(subject=username, scopes=[])
    own_id = employee_records["own"]["id"]
    response = client.get(
        f"/employees/{own_id}", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("username", HR_ACCOUNTS)
def test_missing_employee_returns_404_for_authorized_hr(
    client, auth_headers, employee_records, username
):
    missing_id = max(record["id"] for record in employee_records.values()) + 1
    response = client.get(
        f"/employees/{missing_id}", headers=auth_headers(username)
    )
    assert response.status_code == 404
