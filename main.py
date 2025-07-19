# --- Standard library imports ---
import os
import re
from datetime import datetime, timedelta
from typing import Optional

# --- Third-party imports ---
from dotenv import load_dotenv
import httpx
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import select
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import (
    FastAPI, HTTPException, Query, Request, Body, Depends, status
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import (
    BaseModel, Field, constr, condecimal, conint, validator, EmailStr
)
from email.message import EmailMessage
import aiosmtplib
import secrets
import anthropic

# --- Load environment variables ---
load_dotenv()

# --- Environment variables ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
VECTARA_API_KEY = os.getenv("VECTARA_API_KEY")
VECTARA_CUSTOMER_ID = os.getenv("VECTARA_CUSTOMER_ID")
VECTARA_CORPUS_ID = os.getenv("VECTARA_CORPUS_ID")
VECTARA_MCP_URL = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# --- FastAPI app ---
app = FastAPI()

# --- Auth config ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# --- SQLAlchemy async setup ---
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

# --- User DB model ---
class UserDB(Base):
    __tablename__ = "users"
    id = sa.Column(sa.Integer, primary_key=True, index=True)
    email = sa.Column(sa.String, unique=True, index=True, nullable=False)
    full_name = sa.Column(sa.String, nullable=True)
    hashed_password = sa.Column(sa.String, nullable=False)
    disabled = sa.Column(sa.Boolean, default=False)
    is_confirmed = sa.Column(sa.Boolean, default=False)
    confirm_token = sa.Column(sa.String, nullable=True)

# --- Pydantic models ---
class User(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    is_confirmed: Optional[bool] = False

class UserInDB(User):
    hashed_password: str
    confirm_token: Optional[str] = None

# --- DB utility ---
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str, db: AsyncSession):
    result = await db.execute(select(UserDB).where(UserDB.email == email))
    user_row = result.scalar_one_or_none()
    if user_row:
        return UserInDB(
            email=user_row.email,
            full_name=user_row.full_name,
            disabled=user_row.disabled,
            hashed_password=user_row.hashed_password
        )
    return None

async def authenticate_user(email: str, password: str, db: AsyncSession):
    user = await get_user(email, db)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(email, db)
    if user is None:
        raise credentials_exception
    return user

# --- Auth endpoints ---

# Email confirmation settings (customize as needed)
EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@example.com")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
APP_URL = os.getenv("APP_URL", "https://virustotal-security-checker-1ba82364afaa.herokuapp.com")

async def send_confirmation_email(to_email: str, token: str):
    msg = EmailMessage()
    msg["Subject"] = "Confirm your registration"
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    confirm_link = f"{APP_URL}/confirm_email?token={token}"
    msg.set_content(f"Thank you for registering. Please confirm your email by clicking this link: {confirm_link}")
    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        username=SMTP_USER,
        password=SMTP_PASS,
        start_tls=True
    )

@app.post("/register")
async def register(
    email: EmailStr = Body(...),
    password: str = Body(...),
    full_name: str = Body(None),
    db: AsyncSession = Depends(get_db)
):
    # Check if user exists
    result = await db.execute(select(UserDB).where(UserDB.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    token = secrets.token_urlsafe(32)
    user_db = UserDB(email=email, full_name=full_name, hashed_password=hashed_password, disabled=False, is_confirmed=False, confirm_token=token)
    db.add(user_db)
    await db.commit()
    try:
        await send_confirmation_email(email, token)
    except Exception as e:
        return {"msg": "User registered, but failed to send confirmation email.", "error": str(e)}
    return {"msg": "User registered successfully. Please check your email to confirm your account."}

@app.get("/confirm_email")
async def confirm_email(token: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserDB).where(UserDB.confirm_token == token))
    user = result.scalar_one_or_none()
    if not user:
        return HTMLResponse("<h3>Invalid or expired confirmation link.</h3>", status_code=404)
    user.is_confirmed = True
    user.confirm_token = None
    db.add(user)
    await db.commit()
    return HTMLResponse("<h3>Email confirmed! You can now log in.</h3>")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user": {"email": user.email, "full_name": user.full_name}}

@app.post("/logout")
async def logout():
    # For JWT, logout is handled client-side by deleting the token
    return {"msg": "Logged out"}

# --- Create DB tables at startup ---
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# --- Vectara Search Endpoint ---
class VectaraSearchRequest(BaseModel):
    query: str
    top_k: int = 5

@app.post("/vectara/search")
async def search_vectara(request: VectaraSearchRequest):
    """
    Search the Vectara corpus for relevant documents.
    """
    if not (VECTARA_API_KEY and VECTARA_CUSTOMER_ID and VECTARA_CORPUS_ID):
        raise HTTPException(status_code=500, detail="Vectara API credentials not configured")
    vectara_url = "https://api.vectara.io/v1/query"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {VECTARA_API_KEY}",
        "customer-id": VECTARA_CUSTOMER_ID
    }
    payload = {
        "query": [
            {
                "query": request.query,
                "corpusKey": [{
                    "customerId": VECTARA_CUSTOMER_ID,
                    "corpusId": VECTARA_CORPUS_ID
                }],
                "numResults": request.top_k
            }
        ]
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(vectara_url, headers=headers, json=payload)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Vectara search error: {response.text}")
        return JSONResponse(content=response.json())

# Load environment variables from .env file
load_dotenv()


# FastAPI application for managing items and researching domains using VirusTotal API.
app = FastAPI()

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Home page route
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
from pydantic import validator

# Pydantic models for input validation
class IPInput(BaseModel):
    value: str
    @validator('value')
    def valid_ip(cls, v):
        # Accepts plain IPv4 or IPv4 with CIDR
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        cidr_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
        if not (re.match(ip_pattern, v) or re.match(cidr_pattern, v)):
            raise ValueError("Invalid IP address format. Accepts IPv4 or IPv4/CIDR.")
        return v

class HashInput(BaseModel):
    value: str
    @validator('value')
    def valid_hash(cls, v):
        # Accepts MD5, SHA1, SHA256
        if not re.match(r"^[a-fA-F0-9]{32}$", v) and not re.match(r"^[a-fA-F0-9]{40}$", v) and not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("Invalid hash format")
        return v

# In-memory storage for items
items = {}


class Item(BaseModel):
    # Name of the item in 1-50 characters, only letters, spaces, hyphens, and apostrophes allowed
    name: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-zA-Z\s\-']+$")
    # Description of the item in 1-200 characters, cannot be empty
    description: str = Field(..., min_length=1, max_length=200)
    # Price of the item, must be a positive decimal number(float, > 0)
    price: float = Field(..., gt=0)
    # Quantity of the item, must be zero or a positive integer(int, >= 0)
    quantity: int = Field(..., ge=0)

    class Config:
        schema_extra = {
            "example": {
                "name": "Example Item",
                "description": "A sample item for demonstration.",
                "price": 9.99,
                "quantity": 5
            }
        }


# Creating new item with its data like name(string), description(string), price(number), and quantity(number)   
@app.post("/items/{item_id}")
def create_item(item_id: int, item: Item):
    # This returns the newly created item with validated fields it's ID and details
    # If the item already exists, it raises an HTTPException with a 400 status code.
    if item_id in items:
        raise HTTPException(status_code=400, detail="Item already exists")
    # Store the item as a dictionary in the in-memory storage with its ID as the key and it's data as value.
    items[item_id] = item.model_dump()
    # Summary message indicating successful creation of the item with its concatenated name and description. 
    summary = f"Item '{item.name}' with description {item.description} created successfully."
    # The response that is returned include a summary field with the concatenated name and description of the item.
    return {"item_id": item_id, **items[item_id], "summary": summary}


# Read or retrieve an item by its ID.
@app.get("/items/{item_id}")
def read_item(item_id: int):
    
    # Returns the item with the specified ID and its details.
    # If the item is not found then it raises an HTTPExecption with a 404 status code.
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item_id": item_id, **items[item_id]}

# Update the value of an existing item with new item data including name(string), description(string), price(number), and quantity(number).
@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    
    # Update an existing item with validated fields.
    # If the item is not found, then it raises an HTTPException with a 404 status code.
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found") 
    # Update the item with the new data provided in the request body.   
    items[item_id] = item.model_dump()
    # A summary message indicating successful update of the item with its concatenated name and description.
    summary = f"Item '{item.name}' with description {item.description} updated successfully."
    # The response includes the updated item details and a summary field with the concatenated name and description of the item.
    return {"item_id": item_id, **items[item_id], "summary": summary}

# Delete an item by its ID."""
@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    
    # Deletes the item with the specified ID and returns a success message indicating successful deletion.
    # If the item is not found, it raises an HTTPException with a 404 status code.
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    del items[item_id]
    return {"detail": "Item deleted"}


def is_valid_domain(domain: str) -> bool:
    # Validates if the input string is a valid domain name by matching it with regular expression pattern
    # Starts with a letter or number, followed by letters, numbers, or hyphens
    pattern = r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$"
    # The pattern allows for multiple subdomains and ensures that the domain ends with a valid top-level domain of at least two characters.
    # The pattern also ensures that the domain does not start or end with a hyphen.
    return re.match(pattern, domain) is not None

# Endpoint to research a domain using VirusTotal API v3
@app.get("/research_domain")
async def research_domain(value: str = Query(..., description="Domain name to research")):
    if not is_valid_domain(value):
        raise HTTPException(status_code=400, detail="Invalid domain name format")
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")
    url = f"https://www.virustotal.com/api/v3/domains/{value}"
    headers = {"x-apikey": VT_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error fetching data from VirusTotal")
        vt_data = response.json()
    parsed = parse_vt_v3_response(vt_data, "domain")
    # Automated Vectara upload (fire and forget)
    try:
        vectara_url = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")
        vectara_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_payload = {
            "corpusId": os.getenv('VECTARA_CORPUS_ID'),
            "document": {
                "documentId": parsed.get("id", value),
                "title": f"VirusTotal Domain Report: {value}",
                "metadataJson": {"type": "domain", "id": parsed.get("id", value)},
                "section": [
                    {"text": vt_report_to_text(vt_data, "domain")}
                ]
            }
        }
        import asyncio
        async def upload_vectara():
            async with httpx.AsyncClient() as client:
                await client.post(vectara_url, headers=vectara_headers, json=vectara_payload)
        asyncio.create_task(upload_vectara())
    except Exception:
        pass

    # --- Vectara RAG search for this domain ---
    vectara_search_results = None
    try:
        vectara_query_url = "https://api.vectara.io/v1/query"
        vectara_search_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_search_payload = {
            "query": [
                {
                    "query": value,
                    "corpusKey": [{
                        "customerId": os.getenv('VECTARA_CUSTOMER_ID'),
                        "corpusId": os.getenv('VECTARA_CORPUS_ID')
                    }],
                    "numResults": 3
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            search_response = await client.post(vectara_query_url, headers=vectara_search_headers, json=vectara_search_payload)
            if search_response.status_code == 200:
                vectara_search_results = search_response.json()
            else:
                vectara_search_results = {"error": f"Vectara search error: {search_response.text}"}
    except Exception as e:
        vectara_search_results = {"error": str(e)}

    # --- Call Claude with both VirusTotal and Vectara data ---
    prompt = f"You are a security analyst. Here is a VirusTotal report for the domain '{value}':\n{vt_report_to_text(vt_data, 'domain')}\n\nHere are relevant snippets from the Vectara corpus:\n"
    if vectara_search_results and 'query' in vectara_search_results and vectara_search_results['query']:
        for result in vectara_search_results['query'][0].get('result', []):
            snippet = result.get('text', '')
            score = result.get('score', 0)
            prompt += f"- (Score: {score:.2f}) {snippet}\n"
    else:
        prompt += "No relevant Vectara results found.\n"
    prompt += "\nSummarize the findings and answer: What do you know about this domain?"
    try:
        claude_summary = ask_claude(prompt)
    except Exception as e:
        claude_summary = f"Claude summary unavailable: {str(e)}"

    return {
        "virustotal": parsed,
        "vectara": vectara_search_results,
        "claude_summary": claude_summary
    }

# Endpoint to research an IP address using VirusTotal API v3
@app.get("/research_ip")
async def research_ip(value: str = Query(..., description="IP address to research")):
    try:
        IPInput(value=value)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    headers = {"x-apikey": VT_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error fetching data from VirusTotal")
        vt_data = response.json()
    parsed = parse_vt_v3_response(vt_data, "ip")
    # Automated Vectara upload (fire and forget)
    try:
        vectara_url = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")
        vectara_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_payload = {
            "corpusId": os.getenv('VECTARA_CORPUS_ID'),
            "document": {
                "documentId": parsed.get("id", value),
                "title": f"VirusTotal IP Report: {value}",
                "metadataJson": {"type": "ip", "id": parsed.get("id", value)},
                "section": [
                    {"text": vt_report_to_text(vt_data, "ip")}
                ]
            }
        }
        import asyncio
        async def upload_vectara():
            async with httpx.AsyncClient() as client:
                await client.post(vectara_url, headers=vectara_headers, json=vectara_payload)
        asyncio.create_task(upload_vectara())
    except Exception:
        pass

    # --- Vectara RAG search for this IP ---
    vectara_search_results = None
    try:
        vectara_query_url = "https://api.vectara.io/v1/query"
        vectara_search_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_search_payload = {
            "query": [
                {
                    "query": value,
                    "corpusKey": [{
                        "customerId": os.getenv('VECTARA_CUSTOMER_ID'),
                        "corpusId": os.getenv('VECTARA_CORPUS_ID')
                    }],
                    "numResults": 3
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            search_response = await client.post(vectara_query_url, headers=vectara_search_headers, json=vectara_search_payload)
            if search_response.status_code == 200:
                vectara_search_results = search_response.json()
            else:
                vectara_search_results = {"error": f"Vectara search error: {search_response.text}"}
    except Exception as e:
        vectara_search_results = {"error": str(e)}

    # --- Call Claude with both VirusTotal and Vectara data ---
    prompt = f"You are a security analyst. Here is a VirusTotal report for the IP '{value}':\n{vt_report_to_text(vt_data, 'ip')}\n\nHere are relevant snippets from the Vectara corpus:\n"
    if vectara_search_results and 'query' in vectara_search_results and vectara_search_results['query']:
        for result in vectara_search_results['query'][0].get('result', []):
            snippet = result.get('text', '')
            score = result.get('score', 0)
            prompt += f"- (Score: {score:.2f}) {snippet}\n"
    else:
        prompt += "No relevant Vectara results found.\n"
    prompt += "\nSummarize the findings and answer: What do you know about this IP?"
    try:
        claude_summary = ask_claude(prompt)
    except Exception as e:
        claude_summary = f"Claude summary unavailable: {str(e)}"

    return {
        "virustotal": parsed,
        "vectara": vectara_search_results,
        "claude_summary": claude_summary
    }

# Endpoint to research a file hash using VirusTotal API v3
@app.get("/research_hash")
async def research_hash(value: str = Query(..., description="File hash to research")):
    try:
        HashInput(value=value)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")
    url = f"https://www.virustotal.com/api/v3/files/{value}"
    headers = {"x-apikey": VT_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error fetching data from VirusTotal")
        vt_data = response.json()
    parsed = parse_vt_v3_response(vt_data, "hash")
    # Automated Vectara upload (fire and forget)
    try:
        vectara_url = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")
        vectara_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_payload = {
            "corpusId": os.getenv('VECTARA_CORPUS_ID'),
            "document": {
                "documentId": parsed.get("id", value),
                "title": f"VirusTotal Hash Report: {value}",
                "metadataJson": {"type": "hash", "id": parsed.get("id", value)},
                "section": [
                    {"text": vt_report_to_text(vt_data, "hash")}
                ]
            }
        }
        import asyncio
        async def upload_vectara():
            async with httpx.AsyncClient() as client:
                await client.post(vectara_url, headers=vectara_headers, json=vectara_payload)
        asyncio.create_task(upload_vectara())
    except Exception:
        pass

    # --- Vectara RAG search for this hash ---
    vectara_search_results = None
    try:
        vectara_query_url = "https://api.vectara.io/v1/query"
        vectara_search_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('VECTARA_API_KEY')}",
            "customer-id": os.getenv('VECTARA_CUSTOMER_ID')
        }
        vectara_search_payload = {
            "query": [
                {
                    "query": value,
                    "corpusKey": [{
                        "customerId": os.getenv('VECTARA_CUSTOMER_ID'),
                        "corpusId": os.getenv('VECTARA_CORPUS_ID')
                    }],
                    "numResults": 3
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            search_response = await client.post(vectara_query_url, headers=vectara_search_headers, json=vectara_search_payload)
            if search_response.status_code == 200:
                vectara_search_results = search_response.json()
            else:
                vectara_search_results = {"error": f"Vectara search error: {search_response.text}"}
    except Exception as e:
        vectara_search_results = {"error": str(e)}

    # --- Call Claude with both VirusTotal and Vectara data ---
    prompt = f"You are a security analyst. Here is a VirusTotal report for the hash '{value}':\n{vt_report_to_text(vt_data, 'hash')}\n\nHere are relevant snippets from the Vectara corpus:\n"
    if vectara_search_results and 'query' in vectara_search_results and vectara_search_results['query']:
        for result in vectara_search_results['query'][0].get('result', []):
            snippet = result.get('text', '')
            score = result.get('score', 0)
            prompt += f"- (Score: {score:.2f}) {snippet}\n"
    else:
        prompt += "No relevant Vectara results found.\n"
    prompt += "\nSummarize the findings and answer: What do you know about this file hash?"
    try:
        claude_summary = ask_claude(prompt)
    except Exception as e:
        claude_summary = f"Claude summary unavailable: {str(e)}"

    return {
        "virustotal": parsed,
        "vectara": vectara_search_results,
        "claude_summary": claude_summary
    }

from fastapi.responses import PlainTextResponse

# Helper to parse VirusTotal v3 response for UI
def parse_vt_v3_response(vt_data, typ):
    try:
        data = vt_data.get("data", {})
        attributes = data.get("attributes", {})
        id_ = data.get("id", "")
        status = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", None)
        vendors = attributes.get("last_analysis_results", {})
        vendor_results = {k: {"result": v.get("result", "clean"), "category": v.get("category", "")} for k, v in vendors.items()}
        # Determine overall status
        malicious = status.get("malicious", 0)
        suspicious = status.get("suspicious", 0)
        harmless = status.get("harmless", 0)
        undetected = status.get("undetected", 0)
        total = sum(status.values())
        last_analysis_date = attributes.get("last_analysis_date", None)
        vt_permalink = f"https://www.virustotal.com/gui/{typ}/{id_}" if id_ else None
        # API quota info (if present)
        api_info = vt_data.get("meta", {}).get("api_info", {})
        if malicious:
            overall = "Malicious"
        elif suspicious:
            overall = "Suspicious"
        elif harmless and not (malicious or suspicious):
            overall = "Harmless"
        else:
            overall = "Unknown"
        return {
            "type": typ,
            "id": id_,
            "status": overall,
            "reputation": reputation,
            "vendors": vendor_results,
            "stats": status,
            "total_vendors": total,
            "last_analysis_date": last_analysis_date,
            "vt_permalink": vt_permalink,
            "api_info": api_info
        }
    except Exception:
        return {"error": "Could not parse VirusTotal response."}

# Helper to create a text summary from VirusTotal v3 response
def vt_report_to_text(vt_data, typ):
    parsed = parse_vt_v3_response(vt_data, typ)
    if "error" in parsed:
        return "Could not parse VirusTotal response."
    lines = []
    lines.append(f"VirusTotal {typ.title()} Report")
    lines.append(f"ID: {parsed['id']}")
    lines.append(f"Status: {parsed['status']}")
    if parsed.get('reputation') is not None:
        lines.append(f"Reputation: {parsed['reputation']}")
    lines.append(f"Total Vendors: {parsed['total_vendors']}")
    lines.append(f"Last Analysis Date: {parsed['last_analysis_date']}")
    lines.append(f"Permalink: {parsed['vt_permalink']}")
    lines.append("")
    lines.append("Vendor Results:")
    for vendor, result in parsed['vendors'].items():
        lines.append(f"- {vendor}: {result['result']} ({result['category']})")
    lines.append("")
    lines.append(f"Stats: {parsed['stats']}")
    if parsed.get('api_info'):
        lines.append(f"API Info: {parsed['api_info']}")
    return "\n".join(lines)

# Endpoint to download VirusTotal report as text
@app.get("/download_report_text")
async def download_report_text(value: str = Query(..., description="Domain, IP, or hash to research"), typ: str = Query(..., description="Type: domain, ip, or hash")):
    """
    Download a VirusTotal report as a plain text file. typ must be one of: domain, ip, hash.
    """
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")
    if typ == "domain":
        if not is_valid_domain(value):
            raise HTTPException(status_code=400, detail="Invalid domain name format")
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif typ == "ip":
        try:
            IPInput(value=value)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif typ == "hash":
        try:
            HashInput(value=value)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        url = f"https://www.virustotal.com/api/v3/files/{value}"
    else:
        raise HTTPException(status_code=400, detail="Invalid type. Must be one of: domain, ip, hash.")
    headers = {"x-apikey": VT_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error fetching data from VirusTotal")
        vt_data = response.json()
    text_report = vt_report_to_text(vt_data, typ)
    filename = f"{typ}_report_{value}.txt"
    return PlainTextResponse(text_report, headers={"Content-Disposition": f"attachment; filename={filename}"})
    

# Vectara integration
import anthropic

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

VECTARA_API_KEY = os.getenv("VECTARA_API_KEY")
VECTARA_CUSTOMER_ID = os.getenv("VECTARA_CUSTOMER_ID")
VECTARA_CORPUS_ID = os.getenv("VECTARA_CORPUS_ID")
VECTARA_MCP_URL = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")

from fastapi import Body

class VectaraUploadRequest(BaseModel):
    doc_id: str
    text: str
    metadata: dict = {}

# Endpoint to upload a text report to Vectara corpus
@app.post("/vectara/upload_report")
async def upload_report_to_vectara(request: VectaraUploadRequest):
    """
    Upload a text report to Vectara corpus for RAG/search.
    """
    if not (VECTARA_API_KEY and VECTARA_CUSTOMER_ID and VECTARA_CORPUS_ID):
        raise HTTPException(status_code=500, detail="Vectara API credentials not configured")
    vectara_url = VECTARA_MCP_URL
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {VECTARA_API_KEY}",
        "customer-id": VECTARA_CUSTOMER_ID
    }
    payload = {
        "corpusId": VECTARA_CORPUS_ID,
        "document": {
            "documentId": request.doc_id,
            "title": request.metadata.get("title", request.doc_id),
            "metadataJson": request.metadata,
            "section": [
                {
                    "text": request.text
                }
            ]
        }
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(vectara_url, headers=headers, json=payload)
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Vectara API error: {response.text}")
        return {"detail": "Uploaded to Vectara", "vectara_response": response.json()}

def ask_claude(prompt: str, max_tokens: int = 300) -> str:
    if not ANTHROPIC_API_KEY:
        return "Claude API key not configured."
    try:
        message = f"{anthropic.HUMAN_PROMPT} {prompt}{anthropic.AI_PROMPT}"
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": message}
            ]
        )
        return response.content[0].text.strip()
    except Exception as e:
        return f"Claude API error: {str(e)}"