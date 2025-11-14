"""
Database Schemas for the AI Chat App

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

# Users
class User(BaseModel):
    email: EmailStr
    name: str = Field(..., description="Display name")
    password_hash: Optional[str] = Field(None, description="BCrypt password hash")
    avatar_url: Optional[str] = None
    is_active: bool = True

# Chats
class Chat(BaseModel):
    user_id: str = Field(..., description="Owner user _id as string")
    title: str = Field("New Chat", description="Chat title")
    model: str = Field("Aurora-1", description="Selected AI model name")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# Messages
class Message(BaseModel):
    chat_id: str
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str
    created_at: Optional[datetime] = None

# Auth payloads
class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CreateChatRequest(BaseModel):
    title: Optional[str] = None
    model: Optional[str] = None

class RenameChatRequest(BaseModel):
    title: str

class SendMessageRequest(BaseModel):
    content: str

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[str] = None
