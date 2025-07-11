
# VirusTotal Security Checker (FastAPI Web App)

A modern, full-stack web application for checking the security status of domains, IP addresses, and file hashes using the VirusTotal API v3. Built with FastAPI, Python, HTML, CSS, and JavaScript.

---


## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Validation & Security](#validation--security)
- [User Guidance](#user-guidance)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## User Guidance

### How to Use the VirusTotal Security Checker

1. **Select Type:** Choose whether you want to check a Domain, IP Address, or File Hash from the dropdown menu.
2. **Enter Value:** Input the domain name (e.g., example.com), IP address, or file hash (MD5, SHA1, or SHA256).
   - For IP research, you can enter either a plain IPv4 address (e.g., "192.0.2.1") or an IPv4 address with CIDR notation (e.g., "192.0.2.0/24") according to your preference.
3. **Check Security:** Click the "Check Security" button to analyze the input using VirusTotal.

4. **View Results:**

    - See the overall status (Malicious, Suspicious, Harmless, Undetected) with color-coded badges.
    - Review detection statistics and a progress bar for a quick overview.
    - Filter vendor results by threat category using the provided buttons.
    - Click the link to view the full VirusTotal report for more details.
    - Download the JSON report for your records.

5. **API Quota:** If available, your remaining VirusTotal API quota is displayed at the bottom of the results.

**Note:** No user data is stored or logged. For best security, always use your own VirusTotal API key and deploy over HTTPS.

---



## Features

- Check domains, IP addresses, and file hashes for security status (malicious, suspicious, harmless, undetected)
- Detailed vendor analysis with filtering by threat category
- Detection statistics with colored badges and progress bars
- Last analysis date and direct link to full VirusTotal report
- Downloadable JSON report for each lookup
- User-friendly, modern UI with Bootstrap and custom styles
- API usage quota display (if available)

## Tech Stack

- **Backend:** FastAPI (Python 3.9+), Pydantic, httpx
- **Frontend:** HTML, CSS, Vanilla JS, Bootstrap
- **API Integration:** VirusTotal API v3
- **Validation:** Pydantic models and custom validators
- **Deployment:** GitHub, Heroku (or any cloud platform)

---



## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/hello_world_fastapi.git
    cd hello_world_fastapi
    ```

2. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3. **Set up environment variables:**

    - Create a `.env` file in the project root:

      ```env
      VT_API_KEY=your_virustotal_api_key_here
      ```

---



## Usage

1. **Run the application:**

    ```bash
    uvicorn main:app --reload
    ```


2. **Open your browser and visit:**
    - [http://localhost:8000/](http://localhost:8000/) for the local web interface
    - [http://localhost:8000/docs](http://localhost:8000/docs) for local API docs (Swagger UI)
    - [https://virustotal-security-checker.herokuapp.com/](https://virustotal-security-checker.herokuapp.com/) for the deployed web app on Heroku

---



## API Endpoints

| Method | Endpoint            | Description                        |
|--------|--------------------|------------------------------------|
| GET    | /                  | Home page (web UI)                 |
| GET    | /research_domain   | Check domain security status       |
| GET    | /research_ip       | Check IP address reputation        |
| GET    | /research_hash     | Check file hash against VirusTotal |
| POST   | /items/{item_id}   | (Demo) Create a new item           |
| GET    | /items/{item_id}   | (Demo) Get item by ID              |
| PUT    | /items/{item_id}   | (Demo) Update item                 |
| DELETE | /items/{item_id}   | (Demo) Delete item                 |

---



## Validation & Security

- All user inputs are validated using Pydantic models and regex patterns.
- API keys are stored in a `.env` file (never committed to version control).
- No user data is stored or logged.
- HTTPS is recommended for deployment.

## Screenshots


> _Add screenshots or a demo GIF here to showcase the UI and features._

---



## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements.

---



## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
