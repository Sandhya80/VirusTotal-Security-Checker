from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, constr, condecimal, conint

app = FastAPI()

# In-memory storage for items
items = {}

class Item(BaseModel):    
    # Name of the item in 1-50 characters, only letters, spaces, hyphens, and apostrophes allowed
    name: constr(min_length=1, max_length=50, egex=r"^[a-zA-Z\s\-']+$")
    # Description of the item in 1-200 characters, cannot be empty
    description: constr(min_length=1, max_length=200)
    # Price of the item, must be a positive decimal number(float, > 0)
    price: condecimal(gt=0)
    # Quantity of the item, must be zero or a positive integer(int, >= 0)
    quantity: conint(ge=0)


# Creating new item with its data like name(string), description(string), price(number), and quantity(number)   
@app.post("/items/{item_id}")
def create_item(item_id: int, item: Item):
    # This returns the newly created item with it's ID and details
    # If the item already exists, it raises an HTTPException with a 400 status code.
    if item_id in items:
        raise HTTPException(status_code=400, detail="Item already exists")
    items[item_id] = item.model_dump()
    # Returns the item with its ID and details.
    return {"item_id": item_id, **items[item_id]}


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
    
    # Returns the updated item with its ID and details.
    # If the item is not found, then it raises an HTTPException with a 404 status code.
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    items[item_id] = item.model_dump()
    return {"item_id": item_id, **items[item_id]}

# Delete an item by its ID."""
@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    
    # Deletes the item with the specified ID and returns a success message indicating successful deletion.
    # If the item is not found, it raises an HTTPException with a 404 status code.
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    del items[item_id]
    return {"detail": "Item deleted"}