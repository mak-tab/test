import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

BOOKS_FILE = 'storage.json'
USERS_FILE = 'users.json'

file_lock = threading.Lock()

def setup_storage_files():
    if not os.path.exists(BOOKS_FILE):
        with open(BOOKS_FILE, 'w', encoding='utf-8') as f:
            initial_books = [
                {"id": 1, "title": "The Lord of the Rings", "author": "J.R.R. Tolkien"},
                {"id": 2, "title": "Dune", "author": "Frank Herbert"}
            ]
            json.dump(initial_books, f, indent=2)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)

setup_storage_files()

class BookBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    author: str = Field(..., min_length=1, max_length=100)

class BookCreate(BookBase):
    pass

class Book(BookBase):
    id: int

class UserLogin(BaseModel):
    username: str
    password: str

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserInDB(UserBase):
    hashed_password: str

class User(UserBase):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def read_data(file_path: str) -> List[Dict[str, Any]]:
    with file_lock:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

def write_data(file_path: str, data: List[Dict[str, Any]]):
    with file_lock:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def get_next_id(file_path: str) -> int:
    data = read_data(file_path)
    if not data:
        return 1
    return max(item.get('id', 0) for item in data) + 1

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str) -> Optional[UserInDB]:
    users_db = read_data(USERS_FILE)
    user_dict = next((user for user in users_db if user["username"] == username), None)
    return UserInDB(**user_dict) if user_dict else None

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_active_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username=username)
    if user is None: raise credentials_exception
    return user

limiter = Limiter(key_func=get_remote_address, default_limits=["1000/hour"])
app = FastAPI(title="Library API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/reg", response_model=User, status_code=status.HTTP_201_CREATED)
# @limiter.limit("5/minute")
def register_user(request: Request, user: UserCreate):
    users_db = read_data(USERS_FILE)
    if any(u['username'] == user.username for u in users_db):
        raise HTTPException(status_code=400, detail="Username already registered")
    new_user = UserInDB(username=user.username, hashed_password=get_password_hash(user.password)).model_dump()
    users_db.append(new_user)
    write_data(USERS_FILE, users_db)
    return User(username=user.username)

@app.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, user_credentials: UserLogin):
    user = authenticate_user(user_credentials.username, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_me(current_user: User = Depends(get_current_active_user)):
    users_db = read_data(USERS_FILE)
    users_db_updated = [user for user in users_db if user["username"] != current_user.username]
    write_data(USERS_FILE, users_db_updated)
    return None

@app.get("/books", response_model=List[Book])
def get_all_books():
    return read_data(BOOKS_FILE)

@app.get("/books/{book_id}", response_model=Book)
def get_book_by_id(book_id: int):
    book = next((b for b in read_data(BOOKS_FILE) if b['id'] == book_id), None)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    return book

@app.post("/books", response_model=Book, status_code=status.HTTP_201_CREATED)
def add_book(book: BookCreate, current_user: User = Depends(get_current_active_user)):
    books_db = read_data(BOOKS_FILE)
    new_book = Book(id=get_next_id(BOOKS_FILE), **book.model_dump()).model_dump()
    books_db.append(new_book)
    write_data(BOOKS_FILE, books_db)
    return new_book

@app.put("/books/{book_id}", response_model=Book)
def update_book(book_id: int, book_update: BookCreate, current_user: User = Depends(get_current_active_user)):
    books_db = read_data(BOOKS_FILE)
    book_index = next((i for i, b in enumerate(books_db) if b['id'] == book_id), None)
    if book_index is None:
        raise HTTPException(status_code=404, detail="Book not found")
    updated_book = Book(id=book_id, **book_update.model_dump())
    books_db[book_index] = updated_book.model_dump()
    write_data(BOOKS_FILE, books_db)
    return updated_book

@app.delete("/books/{book_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_book(book_id: int, current_user: User = Depends(get_current_active_user)):
    books_db = read_data(BOOKS_FILE)
    books_db_updated = [b for b in books_db if b['id'] != book_id]
    if len(books_db_updated) == len(books_db):
        raise HTTPException(status_code=404, detail="Book not found")
    write_data(BOOKS_FILE, books_db_updated)
    return None

