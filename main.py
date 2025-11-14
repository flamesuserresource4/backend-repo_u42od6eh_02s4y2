import os
import time
import hashlib
import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document
from schemas import (
    User, Chat, Message,
    RegisterRequest, LoginRequest,
    CreateChatRequest, RenameChatRequest,
    SendMessageRequest, UpdateProfileRequest,
)

# ----------------------------------------------------------------------------
# App & Security
# ----------------------------------------------------------------------------
app = FastAPI(title="AI Chat Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)
    return encoded_jwt


class TokenPayload(BaseModel):
    sub: str
    email: str
    exp: int


def get_user_collection():
    return db["user"]


def get_chat_collection():
    return db["chat"]


def get_message_collection():
    return db["message"]


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        token_data = TokenPayload(**payload)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_doc = get_user_collection().find_one({"_id": token_data.sub})
    if not user_doc:
        # Fallback: some Mongo deployments store ObjectId; allow string matching via _id string
        user_doc = get_user_collection().find_one({"_id": token_data.sub})
    if not user_doc:
        raise HTTPException(status_code=401, detail="User not found")
    return user_doc


# ----------------------------------------------------------------------------
# Utility: safe id conversion
# We'll store ids as strings using create_document's return id; ensure we keep it as string everywhere
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Routes: Health
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "ai-chat-backend"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "collections": [],
    }
    try:
        collections = db.list_collection_names()
        response["collections"] = collections
        response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response

# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
@app.post("/auth/register")
def register(payload: RegisterRequest):
    users = get_user_collection()
    if users.find_one({"email": payload.email.lower()}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email.lower(),
        name=payload.name,
        password_hash=hash_password(payload.password),
    )
    user_id = create_document("user", user)
    access_token = create_access_token({"sub": user_id, "email": user.email})
    return {"token": access_token, "user": {"_id": user_id, "email": user.email, "name": user.name, "avatar_url": user.avatar_url}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    users = get_user_collection()
    doc = users.find_one({"email": payload.email.lower()})
    if not doc or not doc.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": str(doc.get("_id")), "email": doc["email"]})
    return {"token": access_token, "user": {"_id": str(doc.get("_id")), "email": doc["email"], "name": doc.get("name"), "avatar_url": doc.get("avatar_url")}}


@app.get("/me")
async def me(user=Depends(get_current_user)):
    return {"_id": str(user.get("_id")), "email": user.get("email"), "name": user.get("name"), "avatar_url": user.get("avatar_url")}


@app.put("/me")
async def update_me(payload: UpdateProfileRequest, user=Depends(get_current_user)):
    updates = {k: v for k, v in payload.model_dump(exclude_unset=True).items()}
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        get_user_collection().update_one({"_id": user["_id"]}, {"$set": updates})
    new_doc = get_user_collection().find_one({"_id": user["_id"]})
    return {"_id": str(new_doc.get("_id")), "email": new_doc.get("email"), "name": new_doc.get("name"), "avatar_url": new_doc.get("avatar_url")}

# ----------------------------------------------------------------------------
# Chats
# ----------------------------------------------------------------------------
@app.get("/chats")
async def list_chats(user=Depends(get_current_user)):
    chats = list(get_chat_collection().find({"user_id": str(user["_id"])}, {"title": 1, "model": 1, "updated_at": 1}))
    for c in chats:
        c["_id"] = str(c.get("_id"))
    chats.sort(key=lambda x: x.get("updated_at", datetime.now(timezone.utc)), reverse=True)
    return chats


@app.post("/chats")
async def create_chat(payload: CreateChatRequest, user=Depends(get_current_user)):
    chat = Chat(
        user_id=str(user["_id"]),
        title=payload.title or "New Chat",
        model=payload.model or "Aurora-1",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    chat_id = create_document("chat", chat)
    return {"_id": chat_id, "title": chat.title, "model": chat.model}


@app.patch("/chats/{chat_id}")
async def rename_chat(chat_id: str, payload: RenameChatRequest, user=Depends(get_current_user)):
    res = get_chat_collection().update_one({"_id": chat_id, "user_id": str(user["_id"])}, {"$set": {"title": payload.title, "updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"ok": True}


@app.delete("/chats/{chat_id}")
async def delete_chat(chat_id: str, user=Depends(get_current_user)):
    get_message_collection().delete_many({"chat_id": chat_id})
    res = get_chat_collection().delete_one({"_id": chat_id, "user_id": str(user["_id"])})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"ok": True}


@app.get("/chats/{chat_id}/messages")
async def list_messages(chat_id: str, user=Depends(get_current_user)):
    chat = get_chat_collection().find_one({"_id": chat_id, "user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    msgs = list(get_message_collection().find({"chat_id": chat_id}).sort("created_at", 1))
    for m in msgs:
        m["_id"] = str(m.get("_id"))
    return msgs


# ----------------------------------------------------------------------------
# Chat Engine (simple local model stub)
# ----------------------------------------------------------------------------

def simple_ai_response(history: List[Dict[str, str]]) -> str:
    # Very small heuristic model: echoes last user prompt with a friendly assistant voice
    last_user = next((m for m in reversed(history) if m["role"] == "user"), None)
    if not last_user:
        return "Hello! How can I help you today?"
    prompt = last_user["content"].strip()
    if not prompt:
        return "I'm here. Ask me anything!"
    # Tiny pseudo-LLM: classify intent and respond
    lower = prompt.lower()
    if "hello" in lower or "hi" in lower:
        return "Hi there! I'm your AI assistant. What would you like to do today?"
    if "help" in lower:
        return "Sure — tell me what you're working on and I’ll guide you step by step."
    if len(prompt) < 12:
        return f"You said: '{prompt}'. Could you share a bit more detail?"
    return (
        "Here's a quick, structured answer based on your question: "
        + prompt[:200]
        + "\n\nKey points:\n- Summarized context awareness\n- Actionable next steps\n- Ask a follow-up for clarity"
    )


@app.post("/chats/{chat_id}/messages")
async def send_message(chat_id: str, payload: SendMessageRequest, user=Depends(get_current_user)):
    chat = get_chat_collection().find_one({"_id": chat_id, "user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # Save user message
    user_msg = Message(chat_id=chat_id, role="user", content=payload.content, created_at=datetime.now(timezone.utc))
    _ = create_document("message", user_msg)

    # Build history and generate assistant reply
    history = list(get_message_collection().find({"chat_id": chat_id}).sort("created_at", 1))
    hist_simple = [{"role": m["role"], "content": m["content"]} for m in history]
    assistant_text = simple_ai_response(hist_simple + [{"role": "user", "content": payload.content}])

    # Save assistant message
    asst_msg = Message(chat_id=chat_id, role="assistant", content=assistant_text, created_at=datetime.now(timezone.utc))
    msg_id = create_document("message", asst_msg)

    # Update chat timestamp
    get_chat_collection().update_one({"_id": chat_id}, {"$set": {"updated_at": datetime.now(timezone.utc)}})

    return {"_id": msg_id, "role": "assistant", "content": assistant_text}


@app.get("/chats/{chat_id}/stream")
async def stream_message(chat_id: str, content: str, user=Depends(get_current_user)):
    chat = get_chat_collection().find_one({"_id": chat_id, "user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # Save user message first
    user_msg = Message(chat_id=chat_id, role="user", content=content, created_at=datetime.now(timezone.utc))
    _ = create_document("message", user_msg)

    history = list(get_message_collection().find({"chat_id": chat_id}).sort("created_at", 1))
    hist_simple = [{"role": m["role"], "content": m["content"]} for m in history] + [{"role": "user", "content": content}]
    full_text = simple_ai_response(hist_simple)

    async def token_stream():
        buffer = []
        for ch in full_text:
            buffer.append(ch)
            # Stream as SSE data events
            yield f"data: {ch}\n\n"
            await asyncio.sleep(0.01)
        # Save assistant message after streaming completes
        asst_msg = Message(chat_id=chat_id, role="assistant", content=full_text, created_at=datetime.now(timezone.utc))
        _ = create_document("message", asst_msg)
        get_chat_collection().update_one({"_id": chat_id}, {"$set": {"updated_at": datetime.now(timezone.utc)}})
        yield "event: done\ndata: [DONE]\n\n"

    return StreamingResponse(token_stream(), media_type="text/event-stream")


# ----------------------------------------------------------------------------
# End
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
