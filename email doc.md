# ZYVENOX API Documentation

**Base URL:** `https://mail.zyvenox.my.id/api`

Temporary email service. Create an inbox and read emails using your address.

## Endpoints

### Domains

#### 1. Get Available Domains
- **Method:** `GET`
- **Path:** `/domains`
- **Description:** Get a list of active domains available for generating and registering email addresses.
- **Response (200 OK):**
  ```json
  {
    "domains": [
      "example1.com",
      "example2.com"
    ]
  }
  ```

---

### Mailboxes

#### 2. Generate Random Email Address
- **Method:** `POST`
- **Path:** `/mailboxes/generate`
- **Description:** Generate a random email address from available domains.
- **Request Body (application/json):**
  ```json
  {
    "domain": "string (optional - to specify which domain to use)"
  }
  ```
- **Response (200 OK):** The generated email address.

#### 3. Register Custom Email Address
- **Method:** `POST`
- **Path:** `/mailboxes/custom`
- **Description:** Register a custom email address with a specific prefix and domain.
- **Request Body (application/json):**
  ```json
  {
    "domain": "string",
    "prefix": "string"
  }
  ```
- **Response (200 OK):** The custom email address.

#### 4. Extract OTP from Latest Email
- **Method:** `GET`
- **Path:** `/mailboxes/{address}/otp`
- **Description:** Extract OTP/code from the latest received email in the specified mailbox.
- **Path Parameters:**
  - `address` (string, required): The target email address.
- **Query Parameters:**
  - `service` (string, optional): Pre-defined regex service (e.g., `gopay`, `openai`).
  - `regex` (string, optional): Custom regex to extract value (e.g., `\\b\\d{6}\\b`).
- **Response (200 OK):**
  ```json
  {
    "otp": "string",
    "from": "string",
    "date": "string"
  }
  ```
- **Error Response (404 Not Found):** Email or OTP not found.

#### 5. Get Emails for a Specific Address
- **Method:** `GET`
- **Path:** `/mailboxes/{address}`
- **Description:** Retrieve a list of emails received by a specific address.
- **Path Parameters:**
  - `address` (string, required): The target email address.
- **Response (200 OK):** List of emails.

#### 6. Delete All Emails in a Mailbox
- **Method:** `DELETE`
- **Path:** `/mailboxes/{address}`
- **Description:** Delete all emails in the specified mailbox (clears the inbox).
- **Path Parameters:**
  - `address` (string, required): The target email address.
- **Response (200 OK):** Inbox cleared.

#### 7. Get a Specific Email
- **Method:** `GET`
- **Path:** `/mailboxes/{address}/{id}`
- **Description:** Retrieve the content of a specific email by its ID.
- **Path Parameters:**
  - `address` (string, required): The target email address.
  - `id` (string, required): The ID of the email.
- **Response (200 OK):** The email content.
- **Error Response (404 Not Found):** Email not found.

#### 8. Delete a Specific Email
- **Method:** `DELETE`
- **Path:** `/mailboxes/{address}/{id}`
- **Description:** Delete a specific email by its ID.
- **Path Parameters:**
  - `address` (string, required): The target email address.
  - `id` (string, required): The ID of the email.
- **Response (200 OK):** Email deleted.
