
from pydantic import BaseModel, Field


class EmployeePublic(BaseModel):
    id: int
    full_name: str
    department: str
    position: str


class EmployeeSensitive(BaseModel):
    id: int
    phone: str
    salary: float


class EmployeeCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    department: str = Field(min_length=2, max_length=100)
    position: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=5, max_length=30)
    salary: float = Field(gt=0)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
