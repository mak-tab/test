from dotenv import load_dotenv
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
TOKEN = int(os.getenv("TOKEN_MINUTE"))

BOOK = 'storage.json'
USER = 'users.json'
FILE = "uploads"

file_lock = threading.Lock()

def create_storage():
    if not os.path.exists(BOOK):
        with open(BOOK, 'w', encoding='utf-8') as f:
            initial_books = [
                {"id": 1, "title": "Chto", "author": "Kto", "cover": None},
                {"id": 2, "title": "Chto-to", "author": "Kto-to", "cover": None}
            ]
            json.dump(initial_books, f, indent=2)
    if not os.path.exists(USER):
        with open(USER, 'w', encoding='utf-8') as f:

            json.dump([], f, indent=2)
    os.makedirs(FILE, exist_ok=True)

create_storage()

class BookBase(BaseModel):
    title: str
    author: str

class BookCreate(BookBase):
    pass

class Book(BookBase):
    id: int
    cover: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

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

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd.verify(plain_password, hashed_password)

def get_hash(password: str) -> str:
    return pwd.hash(password)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str) -> Optional[UserInDB]:
    users_db = read_data(USER)
    user_dict = next((user for user in users_db if user["username"] == username), None)
    return UserInDB(**user_dict) if user_dict else None

def auth_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_curr_act_user(token: str = Depends(oauth)) -> UserInDB:
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

app.mount("/uploads", StaticFiles(directory=FILE), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/reg", response_model=User, status_code=status.HTTP_201_CREATED)
def reg_user(request: Request, user: UserCreate):
    users_db = read_data(USER)
    if any(u['username'] == user.username for u in users_db):
        raise HTTPException(status_code=400, detail="Username already registered")
    new_user = UserInDB(username=user.username, hashed_password=get_hash(user.password)).model_dump()
    users_db.append(new_user)
    write_data(USER, users_db)
    return User(username=user.username)

@app.post("/log", response_model=Token)
async def log_user(request: Request, user_credentials: UserLogin):
    user = auth_user(user_credentials.username, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me", response_model=User)
def show_me(current_user: User = Depends(get_curr_act_user)):
    return current_user

@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def del_me(current_user: User = Depends(get_curr_act_user)):
    users_db = read_data(USER)
    users_db_updated = [user for user in users_db if user["username"] != current_user.username]
    write_data(USER, users_db_updated)
    return None

@app.get("/books", response_model=List[Book])
def get_books(request: Request):
    books = read_data(BOOK)
    for book in books:
        if book.get('cover'):
            book['cover'] = f"{request.base_url}uploads/{book['cover']}"
    return books

@app.get("/books/{book_id}", response_model=Book)
def get_book_by_id(book_id: int, request: Request):
    books_db = read_data(BOOK)
    book = next((b for b in books_db if b['id'] == book_id), None)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    if book.get('cover'):
        book['cover'] = f"{request.base_url}uploads/{book['cover']}"
    return book

@app.post("/books", response_model=Book, status_code=status.HTTP_201_CREATED)
def add_book(book: BookCreate, current_user: User = Depends(get_curr_act_user)):
    books_db = read_data(BOOK)
    new_book = Book(id=get_next_id(BOOK), **book.model_dump()).model_dump()
    books_db.append(new_book)
    write_data(BOOK, books_db)
    return new_book

@app.put("/books/{book_id}", response_model=Book)
def update_book(book_id: int, book_update: BookCreate, current_user: User = Depends(get_curr_act_user)):
    books_db = read_data(BOOK)
    book_index = next((i for i, b in enumerate(books_db) if b['id'] == book_id), None)
    if book_index is None:
        raise HTTPException(status_code=404, detail="Book not found")
    existing_cover = books_db[book_index].get('cover')
    updated_book = Book(id=book_id, **book_update.model_dump())
    updated_book_dict = updated_book.model_dump()
    if existing_cover:
        updated_book_dict['cover'] = existing_cover
    books_db[book_index] = updated_book_dict
    write_data(BOOK, books_db)
    return updated_book_dict

@app.delete("/books/{book_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_book(book_id: int, current_user: User = Depends(get_curr_act_user)):
    books_db = read_data(BOOK)
    book = next((b for b in books_db if b['id'] == book_id), None)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    
    if book.get('cover'):
        cover_path = os.path.join(FILE, book['cover'])
        try:
            os.remove(cover_path)
        except FileNotFoundError:
            pass
    
    books_db_updated = [b for b in books_db if b['id'] != book_id]
    write_data(BOOK, books_db_updated)
    return None

@app.post("/books/{book_id}/cover", status_code=status.HTTP_200_OK)
async def upload_cover(
    book_id: int, 
    file: UploadFile = File(...),
    current_user: User = Depends(get_curr_act_user)
):
    books_db = read_data(BOOK)
    book_index = next((i for i, b in enumerate(books_db) if b['id'] == book_id), None)
    if book_index is None:
        raise HTTPException(status_code=404, detail="Book not found")
    
    file_ext = os.path.splitext(file.filename)[1]
    filename = f"{book_id}_{uuid.uuid4().hex}{file_ext}"
    file_path = os.path.join(FILE, filename)
    
    existing_cover = books_db[book_index].get('cover')
    if existing_cover:
        old_path = os.path.join(FILE, existing_cover)
        try:
            os.remove(old_path)
        except FileNotFoundError:
            pass
    
    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)
    except Exception:
        raise HTTPException(status_code=500, detail="Error saving file")
    finally:
        await file.close()
    
    books_db[book_index]['cover'] = filename
    write_data(BOOK, books_db)
    
    return {"filename": filename, "message": "Cover uploaded successfully"}

@app.delete("/books/{book_id}/cover", status_code=status.HTTP_204_NO_CONTENT)
def delete_cover(book_id: int, current_user: User = Depends(get_curr_act_user)):
    books_db = read_data(BOOK)
    book_index = next((i for i, b in enumerate(books_db) if b['id'] == book_id), None)
    if book_index is None:
        raise HTTPException(status_code=404, detail="Book not found")
    
    cover_filename = books_db[book_index].get('cover')
    if not cover_filename:
        raise HTTPException(status_code=404, detail="No cover exists for this book")
    
    cover_path = os.path.join(FILE, cover_filename)
    try:
        os.remove(cover_path)
    except FileNotFoundError:
        pass
    
    books_db[book_index]['cover'] = None
    write_data(BOOK, books_db)
    return None

