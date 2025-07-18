# Importing load_dotenv to load environment variables from a .env file
from dotenv import load_dotenv
# Importing os for environment variable handling 
import os
# httpx for making HTTP requests
import httpx
# Importing re for regular expression operations
import re
# FastAPI for building the API, HTTPException for error handling, and Pydantic for data validation.
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
# Pydantic for data validation and type checking
from pydantic import BaseModel, constr, condecimal, conint, Field

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
    return parse_vt_v3_response(vt_data, "domain")

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
    return parse_vt_v3_response(vt_data, "ip")

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
    return parse_vt_v3_response(vt_data, "hash")

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
    

# Claude (Anthropic) integration
import anthropic

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def ask_claude(prompt: str, max_tokens: int = 300) -> str:
    if not ANTHROPIC_API_KEY:
        return "Claude API key not configured."
    response = claude_client.completions.create(
        model="claude-3-opus-20240229",
        max_tokens_to_sample=max_tokens,
        prompt=f"{anthropic.HUMAN_PROMPT} {prompt}{anthropic.AI_PROMPT}"
    )
    return response.completion.strip()