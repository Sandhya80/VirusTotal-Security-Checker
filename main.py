# Importing load_dotenv to load environment variables from a .env file
from dotenv import load_dotenv
# Importing os for environment variable handling 
import os
# httpx for making HTTP requests
import httpx
# Importing re for regular expression operations
import re
# FastAPI for building the API, HTTPException for error handling, and Pydantic for data validation.
from fastapi import FastAPI, HTTPException, Query
# Pydantic for data validation and type checking
from pydantic import BaseModel, constr, condecimal, conint

# Load environment variables from .env file
load_dotenv()

# FastAPI application for managing items and researching domains using VirusTotal API.
app = FastAPI()

# In-memory storage for items
items = {}

class Item(BaseModel):    
    # Name of the item in 1-50 characters, only letters, spaces, hyphens, and apostrophes allowed
    name: constr(min_length=1, max_length=50, pattern=r"^[a-zA-Z\s\-']+$")
    # Description of the item in 1-200 characters, cannot be empty
    description: constr(min_length=1, max_length=200)
    # Price of the item, must be a positive decimal number(float, > 0)
    price: condecimal(gt=0)
    # Quantity of the item, must be zero or a positive integer(int, >= 0)
    quantity: conint(ge=0)


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

# Endpoint to research a domain using the VirusTotal API
@app.get("/research_domain")
async def research_domain(
    domain: str = Query(..., description="Domain name to research")
):    # Validates the domain name using the is_valid_domain function
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain name format")
    
    # Get VirusTotal API key from environment variable
    VT_API_KEY = os.getenv("VT_API_KEY")
    # If the API key is not set, raise an HTTPException with a 500 status code
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured")
    # Prepare the API request to VirusTotal
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    # The API endpoint for domain report in VirusTotal
    # The API key is passed as a query parameter along with the domain to be researched.
    params = {"apikey": VT_API_KEY, "domain": domain}
    
    # Make the API request to VirusTotal
    # Using httpx.AsyncClient to make an asynchronous HTTP GET request to the VirusTotal API
    async with httpx.AsyncClient() as client:        
        # The response is awaited to ensure that the request is completed before proceeding.
        response = await client.get(url, params=params)
        # If the response status code is not 200 (OK), raise an HTTPException with a 502 status code
        # indicating that there was an error fetching data from VirusTotal.
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error fetching data from VirusTotal")
        # Parse the JSON response from VirusTotal
        vt_data = response.json()
    return vt_data