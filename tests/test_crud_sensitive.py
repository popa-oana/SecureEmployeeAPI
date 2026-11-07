"""Write permissions, independent role checks, and sensitive-data access."""

from copy import deepcopy

import pytest


PUBLIC_FIELDS = {"id", "full_name", "department", "position"}
SENSITIVE_FIELDS = {"id", "phone", "salary"}
DENIED_ACCESS = [
    pytest.param("no_token", 401, id="no-token"),
    pytest.param("invalid_token", 401, id="invalid-token"),
    pytest.param("employee_demo", 403, id="employee"),
    pytest.param("hr_reader", 403, id="reader"),
    pytest.param("admin_without_scope", 403, id="admin-without-scope"),
    pytest.param("employee_with_scope", 403, id="employee-with-scope"),
    pytest.param("reader_with_scope", 403, id="reader-with-scope"),
]


@pytest.fixture
def employee_store(isolated_state):
    # Import only after the shared fixtures have isolated configuration and data.
    from app.data import EMPLOYEES

    return EMPLOYEES


@pytest.fixture
def employee_payload():
    return {
        "full_name": "Fictional CRUD Employee",
        "department": "Test Operations",
        "position": "Test Analyst",
        "phone": "202-555-0153",
        "salary": 34567.89,
    }


@pytest.fixture
def denied_headers(auth_headers, token_factory, monkeypatch):
    def headers_for(case, required_scope):
        if case == "no_token":
            return {}
        if case == "invalid_token":
            return {"Authorization": "Bearer not-a-jwt"}
        if case == "admin_without_scope":
            scopes = [
                scope for scope in
                ("employees:read", "employees:write", "employees:sensitive")
                if scope != required_scope
            ]
            return {"Authorization": "Bearer " + token_factory(scopes=scopes)}
        if case in ("employee_with_scope", "reader_with_scope"):
            from app.users import USERS

            username = "employee_demo" if case == "employee_with_scope" else "hr_reader"
            # Grant the scope in both the account and its genuinely issued token.
            # The role remains unchanged; monkeypatch and isolated_state restore it.
            monkeypatch.setitem(
                USERS[username], "scopes", [*USERS[username]["scopes"], required_scope]
            )
            return auth_headers(username)
        return auth_headers(case)

    return headers_for


def write_request(client, method, employee_id, payload, headers):
    path = "/employees" if method == "POST" else f"/employees/{employee_id}"
    options = {"headers": headers}
    if method != "DELETE":
        options["json"] = payload
    return client.request(method, path, **options)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
@pytest.mark.parametrize("case, expected_status", DENIED_ACCESS)
def test_denied_write_preserves_all_employees(
    client, employee_records, employee_store, employee_payload,
    denied_headers, method, case, expected_status
):
    headers = denied_headers(case, "employees:write")
    before = deepcopy(employee_store)
    response = write_request(
        client, method, employee_records["own"]["id"], employee_payload, headers
    )
    assert response.status_code == expected_status
    assert employee_store == before


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
@pytest.mark.parametrize("case, expected_status", DENIED_ACCESS)
def test_write_authorization_precedes_resource_lookup(
    client, employee_records, employee_store, employee_payload,
    denied_headers, method, case, expected_status
):
    headers = denied_headers(case, "employees:write")
    before = deepcopy(employee_store)
    own_id = employee_records["own"]["id"]
    missing_id = max(employee_store) + 100
    existing = write_request(client, method, own_id, employee_payload, headers)
    assert existing.status_code == expected_status
    assert employee_store == before
    missing = write_request(client, method, missing_id, employee_payload, headers)
    assert missing.status_code == expected_status
    assert missing.json() == existing.json()
    assert employee_store == before


def test_admin_creates_employee(
    client, auth_headers, employee_store, employee_payload
):
    headers = auth_headers("hr_admin")
    before = deepcopy(employee_store)
    response = client.post("/employees", headers=headers, json=employee_payload)
    assert response.status_code == 201
    created = response.json()
    new_id = created["id"]
    assert new_id not in before
    expected = {"id": new_id, **employee_payload}
    assert created == {key: expected[key] for key in PUBLIC_FIELDS}
    assert employee_store == {**before, new_id: expected}
    public = client.get(f"/employees/{new_id}", headers=headers)
    assert public.status_code == 200
    assert public.json() == created
    sensitive = client.get(f"/employees/{new_id}/sensitive", headers=headers)
    assert sensitive.status_code == 200
    assert sensitive.json() == {key: expected[key] for key in SENSITIVE_FIELDS}


def test_admin_updates_employee(
    client, auth_headers, employee_records, employee_store, employee_payload
):
    headers = auth_headers("hr_admin")
    before = deepcopy(employee_store)
    employee_id = employee_records["own"]["id"]
    response = client.put(
        f"/employees/{employee_id}", headers=headers, json=employee_payload
    )
    assert response.status_code == 200
    expected = {"id": employee_id, **employee_payload}
    assert response.json() == {key: expected[key] for key in PUBLIC_FIELDS}
    assert employee_store == {**before, employee_id: expected}
    public = client.get(f"/employees/{employee_id}", headers=headers)
    assert public.status_code == 200
    assert public.json() == response.json()
    sensitive = client.get(f"/employees/{employee_id}/sensitive", headers=headers)
    assert sensitive.status_code == 200
    assert sensitive.json() == {key: expected[key] for key in SENSITIVE_FIELDS}


def test_admin_deletes_employee(client, auth_headers, employee_records, employee_store):
    headers = auth_headers("hr_admin")
    before = deepcopy(employee_store)
    employee_id = employee_records["own"]["id"]
    response = client.delete(f"/employees/{employee_id}", headers=headers)
    assert response.status_code == 204
    assert response.content == b""
    assert employee_store == {key: row for key, row in before.items() if key != employee_id}
    assert client.get(f"/employees/{employee_id}", headers=headers).status_code == 404
    assert client.get(
        f"/employees/{employee_id}/sensitive", headers=headers
    ).status_code == 404


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_admin_write_to_missing_employee_returns_404(
    client, auth_headers, employee_store, employee_payload, method
):
    before = deepcopy(employee_store)
    missing_id = max(employee_store) + 100
    response = write_request(
        client, method, missing_id, employee_payload, auth_headers("hr_admin")
    )
    assert response.status_code == 404
    assert employee_store == before


@pytest.mark.parametrize("case, expected_status", DENIED_ACCESS)
@pytest.mark.parametrize("resource_exists", [True, False], ids=["existing", "missing"])
def test_denied_sensitive_access(
    client, employee_records, employee_store, denied_headers,
    case, expected_status, resource_exists
):
    headers = denied_headers(case, "employees:sensitive")
    before = deepcopy(employee_store)
    employee_id = (
        employee_records["own"]["id"] if resource_exists else max(employee_store) + 100
    )
    response = client.get(f"/employees/{employee_id}/sensitive", headers=headers)
    assert response.status_code == expected_status
    assert employee_store == before


@pytest.mark.parametrize("record_name", ["own", "other"])
def test_admin_reads_exact_sensitive_fields(
    client, auth_headers, employee_records, employee_store, record_name
):
    before = deepcopy(employee_store)
    record = employee_records[record_name]
    response = client.get(
        f"/employees/{record['id']}/sensitive", headers=auth_headers("hr_admin")
    )
    assert response.status_code == 200
    # Exact equality excludes all extra account, authentication and internal fields.
    assert response.json() == {key: record[key] for key in SENSITIVE_FIELDS}
    assert employee_store == before


def test_admin_sensitive_access_to_missing_employee_returns_404(
    client, auth_headers, employee_store
):
    before = deepcopy(employee_store)
    missing_id = max(employee_store) + 100
    response = client.get(
        f"/employees/{missing_id}/sensitive", headers=auth_headers("hr_admin")
    )
    assert response.status_code == 404
    assert employee_store == before


@pytest.mark.parametrize("username", ["hr_reader", "hr_admin"])
def test_public_hr_reads_still_exclude_sensitive_fields(
    client, auth_headers, employee_records, username
):
    headers = auth_headers(username)
    response = client.get("/employees", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == len(employee_records)
    assert all(set(record) == PUBLIC_FIELDS for record in response.json())
    for record in employee_records.values():
        response = client.get(f"/employees/{record['id']}", headers=headers)
        assert response.status_code == 200
        assert response.json() == {key: record[key] for key in PUBLIC_FIELDS}


def test_public_employee_read_still_excludes_sensitive_fields(
    client, auth_headers, employee_records
):
    record = employee_records["own"]
    response = client.get(
        f"/employees/{record['id']}", headers=auth_headers("employee_demo")
    )
    assert response.status_code == 200
    assert response.json() == {key: record[key] for key in PUBLIC_FIELDS}
