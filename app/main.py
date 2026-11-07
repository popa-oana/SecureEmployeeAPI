
from fastapi import FastAPI, HTTPException, status, Depends, Security, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.audit import log_success
from app.data import EMPLOYEES
from app.schemas import EmployeePublic, EmployeeSensitive, EmployeeCreate, TokenResponse
from app.security import create_access_token
from app.users import authenticate_user
from app.dependencies import get_current_user


# Application configuration
app = FastAPI(
    title="Secure Employee Management API",
    description=(
        "REST API for managing employees with authentication, "
        "authorization, and sensitive data protection."
    ),
    version="1.0.0"
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Keep actionable validation details without rejected input or raw context.
    errors = [
        {key: error[key] for key in ("loc", "msg", "type")}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": errors}
    )


# Root endpoint

@app.get("/", tags=["General"])
def root():
    return {
        "message": "Secure Employee Management API is running"
    }

# List employees

@app.get(
    "/employees",
    response_model=list[EmployeePublic],
    tags=["Employees"],
    responses={
        401: {"description": "Invalid or missing token"},
        403: {"description": "Insufficient permissions"}
    }
)
def get_employees(
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:read"]
    )
):
    if current_user["role"] not in ("hr_reader", "hr_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to employee list"
        )

    return list(EMPLOYEES.values())

# Get employee by ID

@app.get(
    "/employees/{employee_id}",
    response_model=EmployeePublic,
    tags=["Employees"],
    responses={
        401: {"description": "Invalid or missing token"},
        403: {"description": "Access denied to employee"},
        404: {"description": "Employee not found"}
    }
)
def get_employee(
    employee_id: int,
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:read"]
    )
):
    # Employees can only access their own information
    if current_user["role"] == "employee":
        if current_user["employee_id"] != employee_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this employee"
            )

    # HR users can access any employee
    elif current_user["role"] not in ("hr_reader", "hr_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this employee"
        )

    employee = EMPLOYEES.get(employee_id)

    if employee is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee not found"
        )

    return employee

# Get sensitive employee data

@app.get(
    "/employees/{employee_id}/sensitive",
    response_model=EmployeeSensitive,
    tags=["Employees"],
    description="Requires the hr_admin role and the employees:sensitive scope.",
    responses={
        401: {"description": "Invalid or missing token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Employee not found"}
    }
)
def get_employee_sensitive(
    employee_id: int,
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:sensitive"]
    )
):
    if current_user["role"] != "hr_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    employee = EMPLOYEES.get(employee_id)

    if employee is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee not found"
        )

    sensitive_data = {
        "id": employee["id"],
        "phone": employee["phone"],
        "salary": employee["salary"]
    }

    log_success(current_user["username"], "employee.read_sensitive", employee_id)

    return sensitive_data

# Create employee

@app.post(
    "/employees",
    response_model=EmployeePublic,
    status_code=status.HTTP_201_CREATED,
    tags=["Employees"]
)
def create_employee(
    employee: EmployeeCreate,
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:write"]
    )
):
    if current_user["role"] != "hr_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    new_id = max(EMPLOYEES.keys(), default=0) + 1

    new_employee = {
        "id": new_id,
        **employee.model_dump()
    }

    EMPLOYEES[new_id] = new_employee

    log_success(current_user["username"], "employee.create", new_id)

    return new_employee

# Update employee

@app.put(
    "/employees/{employee_id}",
    response_model=EmployeePublic,
    tags=["Employees"],
    responses={
        404: {"description": "Employee not found"}
    }
)
def update_employee(
    employee_id: int,
    employee: EmployeeCreate,
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:write"]
    )
):
    if current_user["role"] != "hr_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    if employee_id not in EMPLOYEES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee not found"
        )

    updated_employee = {
        "id": employee_id,
        **employee.model_dump()
    }

    EMPLOYEES[employee_id] = updated_employee

    log_success(current_user["username"], "employee.update", employee_id)

    return updated_employee

# Delete employee

@app.delete(
    "/employees/{employee_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Employees"],
    responses={
        404: {"description": "Employee not found"}
    }
)
def delete_employee(
    employee_id: int,
    current_user: dict = Security(
        get_current_user,
        scopes=["employees:write"]
    )
):
    if current_user["role"] != "hr_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    if employee_id not in EMPLOYEES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee not found"
        )

    del EMPLOYEES[employee_id]

    log_success(current_user["username"], "employee.delete", employee_id)

# JWT authentication

@app.post(
    "/token",
    response_model=TokenResponse,
    tags=["Authentication"],
    responses={
        401: {"description": "Incorrect username or password"}
    }
)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(
        form_data.username,
        form_data.password
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token(
        subject=user["username"],
        scopes=user["scopes"]
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
