from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

def validate_password(password: str) -> str:
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
    if not re.match(password_regex, password):
        raise ValueError(
            "Password must be at least 8 characters long and include at least one uppercase letter, "
            "one lowercase letter, one number, and one special character."
        )
    return password  # Add password hashing here before saving to DB

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=6, max_length=30, pattern=r'^[\w-]+$', example=generate_nickname()
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    _validate_urls = validator(
        'profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True
    )(validate_url)

    @validator('nickname')
    def strip_and_validate_nickname(cls, v):
        if v:
            v = v.strip()
            if not re.match(r'^[\w-]+$', v):
                raise ValueError("Nickname must only contain letters, numbers, underscores, and hyphens.")
            # NOTE: Uniqueness should be enforced in the service/db layer
        return v

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

    _validate_password = validator('password', allow_reuse=True)(validate_password)
class UpdateBioRequest(BaseModel):
    bio: str = Field(
        ...,
        max_length=500,
        description="The new bio for the user (max length: 500 characters).",
        example="Intern software developer with a bachelor's degree in Computer Science."
    )

class UpdateProfilePictureRequest(BaseModel):
    profile_picture_url: HttpUrl = Field(
        ...,
        description="The new profile picture URL.",
        example="https://example.com/profiles/john_new.jpg"
    )
    
class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=6, max_length=30, pattern=r'^[\w-]+$', example=generate_nickname()
    )

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update.")
        return values

    @validator('nickname')
    def strip_and_validate_nickname(cls, v):
        if v:
            v = v.strip()
            if not re.match(r'^[\w-]+$', v):
                raise ValueError("Nickname must only contain letters, numbers, underscores, and hyphens.")
        return v

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")  # Must match example in registration

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(),
        "nickname": generate_nickname(),
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced developer",
        "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
