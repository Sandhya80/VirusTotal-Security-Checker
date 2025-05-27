# Hello World FastAPI CRUD API

A simple RESTful API built with FastAPI that demonstrates basic Create, Read, Update, and Delete (CRUD) operations for "Hello World" items, using in-memory storage.  
**Now includes domain research via VirusTotal and secure environment variable management.**

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
- [Security & Environment Variables](#security--environment-variables)
- [License](#license)

---

## Overview

This project provides a minimal FastAPI application with CRUD endpoints for storing and managing simple "Hello World" items in memory.  
It now also allows you to research domain names using the VirusTotal API, with all sensitive keys managed securely.

---

## Features

- FastAPI-based REST API
- In-memory storage (no database required)
- CRUD operations: Create, Read, Update, Delete
- Interactive API documentation via Swagger UI
- **Domain research endpoint using VirusTotal**
- **Strict input validation following OWASP guidelines**
- **Secure environment variable management with `.env` and `.gitignore`**

---

## Requirements

- Python 3.7+
- [FastAPI](https://fastapi.tiangolo.com/)
- [Uvicorn](https://www.uvicorn.org/) (for running the server)
- [python-dotenv](https://pypi.org/project/python-dotenv/) (for loading environment variables)
- [httpx](https://www.python-httpx.org/) (for external API calls)

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

The API provides the following endpoints for managing "Hello World" items and researching domains:

- `GET /items/{item_id}`: Retrieve a specific item by ID
- `POST /items/{item_id}`: Create a new item by ID
- `PUT /items/{item_id}`: Update an existing item by ID
- `DELETE /items/{item_id}`: Delete an item by ID
- **`GET /research_domain?domain=example.com`**: Research a domain using the VirusTotal API

---

## Usage Examples

### Create a new item

```bash
curl -X POST "http://127.0.0.1:8000/items/1" -H "Content-Type: application/json" -d "{\"name\": \"Item 1\", \"description\": \"This is item 1\", \"price\": 10.5, \"quantity\": 2}"
```

### Research a domain

```bash
curl -X GET "http://127.0.0.1:8000/research_domain?domain=example.com"
```

---

## Interactive API Docs

Explore and test the API using the automatically generated Swagger UI documentation:

- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Security & Environment Variables

- **API keys and secrets are stored in a `.env` file** (not tracked by Git).
- **`.env` is listed in `.gitignore`** to keep secrets private.
- The app uses `python-dotenv` to load environment variables securely.
- **Never share your `.env` file or API keys publicly.**

---

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
