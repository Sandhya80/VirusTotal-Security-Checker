from fastapi import FastAPI, HTTPException

app = FastAPI()

# In-memory storage for items
items = {}

# Create an item
@app.post("/items/{item_id}")
def create_item(item_id: int, value: str):
    if item_id in items:
        raise HTTPException(status_code=400, detail="Item already exists")
    items[item_id] = value
    return {"item_id": item_id, "value": value}

# Read an item
@app.get("/items/{item_id}")
def read_item(item_id: int):
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item_id": item_id, "value": items[item_id]}

# Update an item
@app.put("/items/{item_id}")
def update_item(item_id: int, value: str):
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    items[item_id] = value
    return {"item_id": item_id, "value": value}

# Delete an item
@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    if item_id not in items:
        raise HTTPException(status_code=404, detail="Item not found")
    del items[item_id]
    return {"detail": "Item deleted"}