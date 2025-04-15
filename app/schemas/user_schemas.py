import uuid
import re
from typing import Optional, List
from datetime import datetime
from enum import Enum
from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from app.utils.nickname_gen import generate_nickname
from app.utils.security import validate_password
# User roles
class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

# Shared URL validator
def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

# Mock placeholder: Replace this with real DB uniqueness check
def is_nickname_unique(nickname: str) -> bool:
    # Example: return not db.query(User).filter(User.nickname == nickname).first()
    return True  # Replace with actual logic

# Shared nickname validator
def validate_nickname(v: Optional[str]) -> Optional[str]:
    if v:
        v = v.strip()
        if not re.match(r'^[\w-]+$', v):
            raise ValueError("Nickname can only contain letters, numbers, underscores, and hyphens.")
        if not is_nickname_unique(v):
            raise ValueError("Nickname is already taken. Please choose another one.")
    return v

# Base user schema
class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=6, max_length=30, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced developer")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profile.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
    _validate_nickname = validator('nickname', allow_reuse=True)(validate_nickname)

    class Config:
        from_attributes = True
class UpdateProfilePictureRequest(BaseModel):
    profile_picture_url: str = Field(..., example="https://example.com/profile.jpg")

    @validator("profile_picture_url")
    def validate_profile_picture_url(cls, value):
        return validate_url(value)


class UpdateBioRequest(BaseModel):
    bio: str = Field(..., max_length=500, example="Passionate software developer with 5 years of experience.")

class UserCreate(UserBase):
    password: str = Field(..., example="Secure*1234")
    @validator("password", pre=True, always=True)
    def validate_password_field(cls, value):
         if value:
             validate_password(value)  # Raises a ValueError if invalid
         return value


class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=6, max_length=30, pattern=r'^[\w-]+$', example=generate_nickname())

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "last_name": "Doe", "bio": "Experienced developer",
        "role": "AUTHENTICATED", "profile_picture_url": "https://example.com/profile.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
