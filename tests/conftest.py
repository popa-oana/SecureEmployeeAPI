"""Isolated test configuration; application imports must stay inside fixtures."""

import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def test_environment():
    # These are public, fictitious test credentials, never deployment secrets.
    settings = {
        "jwt_key": "pytest-only-fictitious-signing-key-not-for-deployment",
        "passwords": {
            "employee_demo": "pytest-only-employee-password",
            "hr_reader": "pytest-only-reader-password",
            "hr_admin": "pytest-only-admin-password",
        },
    }
    with pytest.MonkeyPatch.context() as environment:
        environment.setenv("PYTHON_DOTENV_DISABLED", "1")
        environment.setenv("JWT_SECRET_KEY", settings["jwt_key"])
        for username, variable in (
            ("employee_demo", "DEMO_EMPLOYEE_PASSWORD"),
            ("hr_reader", "DEMO_READER_PASSWORD"),
            ("hr_admin", "DEMO_ADMIN_PASSWORD"),
        ):
            environment.setenv(variable, settings["passwords"][username])
        yield settings


@pytest.fixture(scope="session")
def application(test_environment):
    if "app.security" in sys.modules:
        pytest.fail("Import the application through fixtures, after test isolation.")
    from app.main import app

    return app


@pytest.fixture
def employee_records(application):
    from app.users import USERS

    own_id = USERS["employee_demo"]["employee_id"]
    return {
        "own": {
            "id": own_id,
            "full_name": "Fictional Employee A",
            "department": "Test IT",
            "position": "Test Developer",
            "phone": "202-555-0141",
            "salary": 12345.67,
        },
        "other": {
            "id": own_id + 1,
            "full_name": "Fictional Employee B",
            "department": "Test HR",
            "position": "Test Specialist",
            "phone": "202-555-0142",
            "salary": 23456.78,
        },
    }


@pytest.fixture(autouse=True)
def isolated_state(application, employee_records):
    from app.data import EMPLOYEES
    from app.users import USERS

    original_employees = deepcopy(EMPLOYEES)
    original_users = deepcopy(USERS)
    try:
        # Preserve dictionary identity: routes and dependencies share these objects.
        EMPLOYEES.clear()
        EMPLOYEES.update(
            {record["id"]: deepcopy(record) for record in employee_records.values()}
        )
        yield
    finally:
        EMPLOYEES.clear()
        EMPLOYEES.update(original_employees)
        USERS.clear()
        USERS.update(original_users)


@pytest.fixture
def client(application, isolated_state):
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture
def login(client, test_environment):
    def authenticate(username):
        response = client.post(
            "/token",
            data={
                "username": username,
                "password": test_environment["passwords"][username],
            },
        )
        assert response.status_code == 200
        return response.json()

    return authenticate


@pytest.fixture
def auth_headers(login):
    def headers_for(username):
        return {"Authorization": "Bearer " + login(username)["access_token"]}

    return headers_for


@pytest.fixture
def token_factory(test_environment):
    """Sign deliberate edge cases with the isolated key, without changing the app."""
    def make_token(
        subject="hr_admin", scopes=None, expires_in=timedelta(minutes=5), key=None
    ):
        return jwt.encode(
            {
                "sub": subject,
                "scopes": ["employees:read", "employees:sensitive"]
                if scopes is None else scopes,
                "exp": datetime.now(timezone.utc) + expires_in,
            },
            test_environment["jwt_key"] if key is None else key,
            algorithm="HS256",
        )

    return make_token


@pytest.fixture(params=["list", "own", "sensitive"])
def protected_get_path(request, employee_records):
    own_id = employee_records["own"]["id"]
    return {
        "list": "/employees",
        "own": f"/employees/{own_id}",
        "sensitive": f"/employees/{own_id}/sensitive",
    }[request.param]


@pytest.fixture
def assert_no_confidential_values(application, test_environment, employee_records):
    """Check outputs without printing even the fictitious secrets on failure."""
    from app.users import USERS

    values = [test_environment["jwt_key"], *test_environment["passwords"].values()]
    values.extend(user["hashed_password"] for user in USERS.values())
    values.extend(
        str(record[field])
        for record in employee_records.values()
        for field in ("phone", "salary")
    )

    def check_output(text, *extra_values):
        if any(str(value) in text for value in (*values, *extra_values)):
            pytest.fail("Output contains a confidential test value.")

    return check_output
