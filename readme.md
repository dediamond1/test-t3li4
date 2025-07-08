# PGP Web Service API Documentation

This document describes the API endpoints available in the PGP Web Service, with examples using Axios in Node.js.

## Base URL
`http://localhost:8080`

## Endpoints

### 1. Server Status
**GET /**  
Check if the server is running.

**Request:**
```javascript
const axios = require('axios');

axios.get('http://localhost:8080')
  .then(response => {
    console.log(response.data);
  })
  .catch(error => {
    console.error('Error:', error.message);
  });
```

**Response:**
```
Server is running
```

### 2. Encrypt Text
**POST /encrypt**  
Encrypts plaintext using PGP encryption.

**Request Body:**
- Plain text string to encrypt

**Example:**
```javascript
const axios = require('axios');

const plaintext = 'This is a secret message';

axios.post('http://localhost:8080/encrypt', plaintext, {
  headers: {
    'Content-Type': 'text/plain'
  }
})
.then(response => {
  console.log('Encrypted:', response.data);
})
.catch(error => {
  console.error('Encryption failed:', error.message);
});
```

**Response:**
```
-----BEGIN PGP MESSAGE-----
[Encrypted content here]
-----END PGP MESSAGE-----
```

### 3. Decrypt Text
**POST /decrypt**  
Decrypts PGP-encrypted text.

**Request Body:**
- PGP encrypted message string

**Example:**
```javascript
const axios = require('axios');

const encrypted = `-----BEGIN PGP MESSAGE-----
[Encrypted content here]
-----END PGP MESSAGE-----`;

axios.post('http://localhost:8080/decrypt', encrypted, {
  headers: {
    'Content-Type': 'text/plain'
  }
})
.then(response => {
  console.log('Decrypted:', response.data);
})
.catch(error => {
  console.error('Decryption failed:', error.message);
});
```

**Response:**
```
This is a secret message
```

## Error Handling
All endpoints return HTTP 200 on success. Errors may include:
- 400 Bad Request: Invalid input format
- 500 Internal Server Error: Encryption/decryption failure

## Notes
1. The service currently accepts plain text only (no JSON)
2. Maximum input size: 1024 bytes
3. Ensure the PGP keys are properly configured on the server
