# FBAuthenticate Azure Function

Azure Functions application for Facebook lead authentication and submission with support for Databricks retry jobs.

## Functions

### 1. FBAutenticate
- **HTTP Trigger**: POST
- **Purpose**: Generates authentication tokens for IP addresses
- **Request Body**: `{ "ip": "192.168.1.1", "timestamp": "2024-01-01T00:00:00Z" }`
- **Response**: `{ "token": "base64-encoded-token" }`

### 2. ListTokens
- **HTTP Trigger**: GET
- **Purpose**: Lists all active tokens in cache
- **Response**: Dictionary of cache keys and tokens

### 3. SubmitLead
- **HTTP Trigger**: POST
- **Purpose**: Submits lead data to external API with authentication and retry logic

## SubmitLead Operation Modes

### Regular Mode (UI Requests)
- **Authentication**: Required via headers:
  - `AuthorizationToken`: Token from FBAutenticate function
  - `AuthorizationId`: Encrypted IP address
- **Response Handling**: Always returns HTTP 200 with `"message": "Lead received"`
- **Failure Handling**: On API failure after retries, writes payload to Event Hub for async processing but still returns success to UI
- **Request Body**: LeadRequest JSON object

### Databricks Retry Mode
- **Authentication**: Skipped entirely
- **Identification**: Via header `X-Retry-Job: true` (configurable)
- **Response Handling**: Returns appropriate status codes:
  - `status: "success"` (200) - API call succeeded
  - `status: "empty"` (200) - API call succeeded but returned empty response
  - `status: "failure"` (500) - API call failed
- **Failure Handling**: Returns error without writing to Event Hub (prevents infinite loops)
- **Purpose**: Process failed leads from Event Hub via Databricks

## Configuration Options

Add these to your Azure Function App Settings or local.settings.json:

```json
{
  "TokenExpiryHours": 24,
  "RetryJobHeaderName": "X-Retry-Job",
  "LeadApiMaxRetries": 3,
  "LeadApiBaseDelayMs": 500,
  "LeadApiTimeoutSeconds": 30,
  "LeadApiUrl": "https://api.example.com/leads",
  "LeadApiUsername": "username",
  "LeadApiPassword": "password",
  "EventHubConnectionString": "connection-string",
  "EventHubName": "event-hub-name"
}
```

## Databricks Integration

When calling from Databricks retry jobs, include the retry header:

```python
import requests

# Example Databricks retry call
headers = {
    "X-Retry-Job": "true",  # This skips authentication
    "Content-Type": "application/json"
}

payload = {
    "Id": {
        "Sequence": "12345",
        "Source": "Facebook",
        "Name": "lead-name"
    },
    "Val": "lead-data-here"
}

response = requests.post(
    "https://your-function-app.azurewebsites.net/api/SubmitLead",
    headers=headers,
    json=payload
)

# Example responses:
# Success: {"status": "success", "message": "Lead processed successfully", "isRetryJob": true, "response": "..."}
# Empty: {"status": "empty", "message": "Lead processed but API returned empty response", "isRetryJob": true, "response": ""}
# Failure: {"status": "failure", "message": "Lead API failed for retry job", "error": "...", "isRetryJob": true}
```

## Flow Diagram

```
UI Request Flow:
Client → FBAutenticate (get token) → SubmitLead (with auth) → Lead API
                                                             ↓ (success/failure)
                                                        HTTP 200 "Lead received"
                                                             ↑ (on API failure)
                                                         Event Hub

Databricks Retry Flow:
Event Hub → Databricks → SubmitLead (X-Retry-Job: true) → Lead API
                                                         ↓ (success: 200, failure: 500)
                                                    Return Status (no Event Hub)
```

## Response Handling

### UI Requests (Regular Mode)
- **Success**: HTTP 200 with `{"message": "Lead received"}`
- **API Failure**: HTTP 200 with `{"message": "Lead received"}` (lead queued to Event Hub)
- **Authentication Failure**: HTTP 400/403 with error details
- **Validation Failure**: HTTP 400 with error details

### Databricks Retry Jobs
- **Success**: HTTP 200 with `"status": "success"`
- **Empty Response**: HTTP 200 with `"status": "empty"`
- **API Failure**: HTTP 500 with `"status": "failure"` (no Event Hub write)
- **Validation Failure**: HTTP 400 with error details (no authentication required)
