import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# БД

DATA = Path(__file__).parent
USERS = DATA / "users.json"
BOOKS = DATA / "books.json"

users_lock = asyncio.Lock()
books_lock = asyncio.Lock()

async def initialize_json_files():
    async with users_lock:
        if not USERS.exists():
            USERS.write_text("[]", encoding="utf-8")
    async with books_lock:
        if not BOOKS.exists():
            BOOKS.write_text("[]", encoding="utf-8")

async def read_data(file_path: Path) -> List[Dict[str, Any]]:
    if not file_path.exists():
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        if not content:
            return []
        return json.loads(content)

async def write_data(file_path: Path, data: List[Dict[str, Any]]):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

async def read_user() -> List[Dict[str, Any]]:
    return await read_data(USERS)

async def write_user(data: List[Dict[str, Any]]):
    async with users_lock:
        await write_data(USERS, data)

async def read_book() -> List[Dict[str, Any]]:
    return await read_data(BOOKS)

async def write_book(data: List[Dict[str, Any]]):
    async with books_lock:
        await write_data(BOOKS, data)


# Pydantic 

class BookBase(BaseModel):
    title: str
    author: str

class BookCreate(BookBase):
    pass

class BookUpdate(BookBase):
    pass

class Book(BookBase):
    id: int
    owner_id: int

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserInDB(UserBase):
    id: int
    hashed_password: str
    tokens_left: int

class User(UserBase):
    id: int
    tokens_left: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# CRUD

async def get_users() -> List[UserInDB]:
    users_raw = await read_user()
    return [UserInDB(**user) for user in users_raw]

async def get_user_by_username(username: str) -> Optional[UserInDB]:
    users = await get_users()
    for user in users:
        if user.username == username:
            return user
    return None

async def create_user(user: UserCreate) -> UserInDB:
    users = await get_users()
    new_id = max([u.id for u in users], default=0) + 1
    hashed_password = password_hash(user.password)
    
    new_user = UserInDB(
        id=new_id,
        username=user.username,
        hashed_password=hashed_password,
        tokens_left=1000
    )
    
    users_dict_list = [u.dict() for u in users]
    users_dict_list.append(new_user.dict())
    await write_user(users_dict_list)
    return new_user

async def update_user(updated_user: UserInDB):
    users = await get_users()
    user_list_dict = [u.dict() for u in users if u.id != updated_user.id]
    user_list_dict.append(updated_user.dict())
    await write_user(user_list_dict)

async def get_books() -> List[Book]:
    books_raw = await read_book()
    return [Book(**book) for book in books_raw]

async def create_book(book: BookCreate, user_id: int) -> Book:
    books = await get_books()
    new_id = max([b.id for b in books], default=0) + 1
    new_book = Book(
        id=new_id,
        title=book.title,
        author=book.author,
        owner_id=user_id
    )
    books_dict_list = [b.dict() for b in books]
    books_dict_list.append(new_book.dict())
    await write_book(books_dict_list)
    return new_book

async def delete_book_id(book_id: int):
    books = await get_books()
    updated_books = [book for book in books if book.id != book_id]
    await write_book([b.dict() for b in updated_books])

async def update_book_crud(book_id: int, book_update: BookUpdate, owner_id: int) -> Optional[Book]:
    books = await get_books()
    updated_book_data = None
    updated_books_list = []
    for book in books:
        if book.id == book_id and book.owner_id == owner_id:
            book.title = book_update.title
            book.author = book_update.author
            updated_book_data = book
        updated_books_list.append(book.dict())
        
    if updated_book_data:
        await write_book(updated_books_list)
        return updated_book_data
    return None

# Аутентификация и безопасность

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

KEY = os.getenv("KEY")
ALGORITHM = os.getenv("ALGORITHM")
TOKEN_MINUTE = int(os.getenv("TOKEN_MINUTE", 30))

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=TOKEN_MINUTE)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ИЗМЕНЕНО: Логика current_user теперь работает с username
async def current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not KEY or not ALGORITHM:
        raise HTTPException(status_code=500, detail="JWT settings are not configured on the server")
        
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_username(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

limiter = Limiter(key_func=get_remote_address)


# FastAPI EndPoints

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="Library API on JSON")

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Try again later.",
    )

@app.on_event("startup")
async def on_startup():
    logging.info("Starting up.")
    await initialize_json_files() 
    logging.info("JSON files ready.")

@app.post("/reg", response_model=User, status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def register_user(user: UserCreate):
    db_user = await get_user_by_username(username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    new_user = await create_user(user=user)
    logging.info(f"User registered: {user.username}")
    return new_user

@app.post("/token", response_model=Token, tags=["Auth"])
@limiter.limit("5/minute")
async def login_for_access_token(request: Request, user_credentials: UserLogin):
    user = await get_user_by_username(username=user_credentials.username)
    if not user or not verify_password(user_credentials.password, user.hashed_password):
        logging.warning(f"Failed login attempt for username: {user_credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_token(data={"sub": user.username})
    logging.info(f"User logged in: {user.username}")
    return {"access_token": access_token, "token_type": "bearer"}

async def check_tokens(user: UserInDB = Depends(current_user)):
    if user.tokens_left <= 0:
        logging.warning(f"User {user.username} has no tokens left.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No API tokens left.")
    
    user.tokens_left -= 1
    await update_user(user) 
    
    logging.info(f"User {user.username} used a token. {user.tokens_left} left.")
    return user

@app.get("/users/me", response_model=User, tags=["Users"])
async def read_users_me(user: UserInDB = Depends(current_user)): 
    return user

@app.post("/books/", response_model=Book, status_code=status.HTTP_201_CREATED, tags=["Books"])
async def create_book_endpoint(book: BookCreate, user: UserInDB = Depends(check_tokens)):
    return await create_book(book=book, user_id=user.id) 

@app.get("/books/", response_model=List[Book], tags=["Books"])
async def read_books_endpoint(user: UserInDB = Depends(check_tokens)):
    return await get_books() 

@app.put("/books/{book_id}", response_model=Book, tags=["Books"])
async def update_book_endpoint(book_id: int, book_update: BookUpdate, user: UserInDB = Depends(check_tokens)):
    updated_book = await update_book_crud(book_id, book_update, user.id)
    if not updated_book:
        raise HTTPException(status_code=404, detail="Book not found or you don't have permission to edit it")
    return updated_book

@app.delete("/books/{book_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Books"])
async def delete_book_endpoint(book_id: int, user: UserInDB = Depends(check_tokens)):
    books = await get_books()
    book_to_delete = next((b for b in books if b.id == book_id), None)
    
    if not book_to_delete:
        raise HTTPException(status_code=404, detail="Book not found")
    if book_to_delete.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions to delete this book")
        
    await delete_book_id(book_id)
    return

import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)