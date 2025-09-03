from pydantic import BaseModel, field_validator
from typing import Optional


class AdvertisementCreateValidator(BaseModel):
    title: str
    description: str

    @field_validator('title')
    @classmethod
    def title_length(cls, v):
        if len(v) < 1 or len(v) > 200:
            raise ValueError('Title must be between 1 and 200 characters')
        return v

    @field_validator('description')
    @classmethod
    def description_length(cls, v):
        if len(v) < 1:
            raise ValueError('Description cannot be empty')
        return v


class AdvertisementUpdateValidator(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

    @field_validator('title')
    @classmethod
    def title_length(cls, v):
        if v is not None and (len(v) < 1 or len(v) > 200):
            raise ValueError('Title must be between 1 and 200 characters')
        return v

    @field_validator('description')
    @classmethod
    def description_length(cls, v):
        if v is not None and len(v) < 1:
            raise ValueError('Description cannot be empty')
        return v


class UserCreateValidator(BaseModel):
    email: str
    password: str

    @field_validator('email')
    @classmethod
    def email_valid(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v

    @field_validator('password')
    @classmethod
    def password_length(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v