
import jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

from app.security import SECRET_KEY, ALGORITHM
from app.users import USERS


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "employees:read": "Read employee information",
        "employees:write": "Create, update, and delete employees",
        "employees:sensitive": "Access sensitive employee data"
    }
)


def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp"]}
        )

        username = payload.get("sub")
        token_scopes = payload.get("scopes")

        if (
            not isinstance(username, str)
            or not isinstance(token_scopes, list)
            or not all(isinstance(s, str) for s in token_scopes)
        ):
            raise credentials_exception

    except jwt.InvalidTokenError:
        raise credentials_exception

    user = USERS.get(username)

    if user is None:
        raise credentials_exception

    for scope in security_scopes.scopes:
        if scope not in token_scopes or scope not in user["scopes"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

    return user
