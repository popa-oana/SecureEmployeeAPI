
import os

from app.security import hash_password, verify_password


USERS = {
    "employee_demo": {
        "username": "employee_demo",
        "role": "employee",
        "employee_id": 1,
        "hashed_password": hash_password(
            os.environ["DEMO_EMPLOYEE_PASSWORD"]
        ),
        "scopes": ["employees:read"]
    },
    "hr_reader": {
        "username": "hr_reader",
        "role": "hr_reader",
        "employee_id": None,
        "hashed_password": hash_password(
            os.environ["DEMO_READER_PASSWORD"]
        ),
        "scopes": ["employees:read"]
    },
    "hr_admin": {
        "username": "hr_admin",
        "role": "hr_admin",
        "employee_id": None,
        "hashed_password": hash_password(
            os.environ["DEMO_ADMIN_PASSWORD"]
        ),
        "scopes": [
            "employees:read",
            "employees:write",
            "employees:sensitive"
        ]
    }
}


DUMMY_PASSWORD_HASH = hash_password("dummy-password")


def authenticate_user(username: str, password: str):
    user = USERS.get(username)

    stored_hash = (
        user["hashed_password"]
        if user is not None
        else DUMMY_PASSWORD_HASH
    )

    if not verify_password(password, stored_hash):
        return None

    return user
