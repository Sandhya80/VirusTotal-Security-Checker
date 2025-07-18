import os
import httpx
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

VECTARA_API_KEY = os.getenv("VECTARA_API_KEY")
VECTARA_CUSTOMER_ID = os.getenv("VECTARA_CUSTOMER_ID")
VECTARA_CORPUS_ID = os.getenv("VECTARA_CORPUS_ID")
VECTARA_MCP_URL = os.getenv("VECTARA_MCP_URL", "https://api.vectara.io/v1/index")


def test_vectara_upload_and_search():
    if not (VECTARA_API_KEY and VECTARA_CUSTOMER_ID and VECTARA_CORPUS_ID):
        print("Vectara API credentials not configured.")
        return

    # Upload a sample document
    upload_url = VECTARA_MCP_URL
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {VECTARA_API_KEY}",
        "customer-id": VECTARA_CUSTOMER_ID
    }
    doc_id = "test-doc-123"
    sample_text = "This is a test document for Vectara upload and search integration."
    payload = {
        "corpusId": VECTARA_CORPUS_ID,
        "document": {
            "documentId": doc_id,
            "title": "Test Document",
            "metadataJson": {"type": "test"},
            "section": [
                {"text": sample_text}
            ]
        }
    }
    print("Uploading document to Vectara...")
    try:
        response = httpx.post(upload_url, headers=headers, json=payload)
        print("Upload status:", response.status_code)
        print("Upload response:", response.text)
    except Exception as e:
        print("Error uploading to Vectara:", e)
        return

    # Search for the document
    search_url = "https://api.vectara.io/v1/query"
    search_payload = {
        "query": [
            {
                "query": "test document",
                "corpusKey": [{
                    "customerId": VECTARA_CUSTOMER_ID,
                    "corpusId": VECTARA_CORPUS_ID
                }],
                "numResults": 3
            }
        ]
    }
    print("Searching Vectara corpus...")
    try:
        search_response = httpx.post(search_url, headers=headers, json=search_payload)
        print("Search status:", search_response.status_code)
        print("Search response:", json.dumps(search_response.json(), indent=2))
    except Exception as e:
        print("Error searching Vectara:", e)

if __name__ == "__main__":
    test_vectara_upload_and_search()
