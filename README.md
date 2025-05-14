# Hello World FastAPI CRUD API

A simple RESTful API built with FastAPI that demonstrates basic Create, Read, Update, and Delete (CRUD) operations for "Hello World" items, using in-memory storage.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Interactive API Docs](#interactive-api-docs)
- [License](#license)

---

## Overview

This project provides a minimal FastAPI application with CRUD endpoints for storing and managing simple "Hello World" items in memory. It is ideal for learning, prototyping, or as a template for more complex APIs.

---

## Features

- FastAPI-based REST API
- In-memory storage (no database required)
- CRUD operations: Create, Read, Update, Delete
- Interactive API documentation via Swagger UI

---

## Requirements

- Python 3.7+
- [FastAPI](https://fastapi.tiangolo.com/)
- [Uvicorn](https://www.uvicorn.org/) (for running the server)

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/hello_world_fastapi.git
   cd hello_world_fastapi
   ```

2. **Install the dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

---

## Running the App

To run the FastAPI app, use the following command:

```bash
uvicorn main:app --reload
```

- `main`: the Python module (main.py) without the .py extension
- `app`: the FastAPI instance inside the main.py file
- `--reload`: enables auto-reload for code changes (development mode)

Visit `http://127.0.0.1:8000` in your browser to access the API.

---

## API Endpoints

The API provides the following endpoints for managing "Hello World" items:

- `GET /items`: Retrieve the list of items
- `GET /items/{item_id}`: Retrieve a specific item by ID
- `POST /items`: Create a new item
- `PUT /items/{item_id}`: Update an existing item by ID
- `DELETE /items/{item_id}`: Delete an item by ID

---

## Usage Examples

### Create a new item

```bash
curl -X POST "http://127.0.0.1:8000/items" -H "Content-Type: application/json" -d "{\"name\": \"Item 1\", \"description\": \"This is item 1\"}"
```

### Get the list of items

```bash
curl -X GET "http://127.0.0.1:8000/items"
```

### Update an item

```bash
curl -X PUT "http://127.0.0.1:8000/items/1" -H "Content-Type: application/json" -d "{\"name\": \"Updated Item 1\", \"description\": \"This is the updated item 1\"}"
```

### Delete an item

```bash
curl -X DELETE "http://127.0.0.1:8000/items/1"
```

---

## Interactive API Docs

Explore and test the API using the automatically generated Swagger UI documentation:

- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
