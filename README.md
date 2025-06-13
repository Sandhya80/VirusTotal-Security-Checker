# Hello World FastAPI

A simple FastAPI application that demonstrates building a modern, high-performance web API with Python.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Pydantic: Data Validation & Parsing](#pydantic-data-validation--parsing)
- [Security & Environment Variables](#security--environment-variables)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- FastAPI framework for building APIs quickly and efficiently
- Automatic interactive API documentation (Swagger UI)
- Type hints for request and response validation
- **Pydantic** for data validation and settings management

---

## Installation

1. **Clone the repository:**
    ```
    git clone https://github.com/yourusername/hello_world_fastapi.git
    cd hello_world_fastapi
    ```

2. **Install dependencies:**
    ```
    pip install -r requirements.txt
    ```

---

## Usage

1. **Run the application:**
    ```
    uvicorn main:app --reload
    ```

2. **Open your browser and visit:**
    - [http://localhost:8000/docs](http://localhost:8000/docs) for interactive API documentation (Swagger UI)
    - [http://localhost:8000/redoc](http://localhost:8000/redoc) for alternative API documentation

---

## API Endpoints

| Method | Endpoint        | Description              |
|--------|----------------|--------------------------|
| GET    | /              | Root endpoint            |
| POST   | /items/        | Create a new item        |

*More endpoints can be added as the project grows.*

---

## Pydantic: Data Validation & Parsing

[Pydantic](https://pydantic-docs.helpmanual.io/) is a Python library for data parsing and validation using Python type annotations. It enforces type hints at runtime and provides user-friendly error messages when data is invalid.

### Why is Pydantic included in this project?

FastAPI uses Pydantic models to define the structure and validation rules for request and response data. By including Pydantic in this project, we ensure:

- **Automatic data validation:** Incoming request data is checked for correctness and completeness.
- **Clear error reporting:** Users receive helpful error messages when data is missing or incorrect.
- **Type safety:** Code is easier to maintain and less error-prone due to explicit data models.

### Usage of Pydantic in This Project

Below is an example of how Pydantic is used in this FastAPI project to define and validate data models:

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Define a Pydantic model for request data validation
class Item(BaseModel):
    name: str
    price: float
    is_offer: bool = None

@app.post("/items/")
async def create_item(item: Item):
    return {"item_name": item.name, "item_price": item.price, "is_offer": item.is_offer}
```

In this example:
- The `Item` class inherits from `BaseModel` (provided by Pydantic).
- FastAPI automatically validates incoming JSON data against the `Item` model.
- If the data is invalid, FastAPI returns a clear error message.

---

## Security & Environment Variables

- Store sensitive information such as API keys and database credentials in a `.env` file.
- Never commit your `.env` file or secrets to version control.
- Use environment variables for configuration whenever possible.

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements.

---

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
