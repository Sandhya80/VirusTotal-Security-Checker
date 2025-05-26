from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, constr, condecimal, conint

app = FastAPI()

# In-memory storage for items
items = {}

class Item(BaseModel):    
    # Name of the item in 1-50 characters, only letters, spaces, hyphens, and apostrophes allowed
    name: constr(min_length=1, max_length=50, regex=r"^[a-zA-Z\s\-']+$")
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