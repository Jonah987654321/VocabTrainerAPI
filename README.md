# API Documentation

## Introduction

This API provides endpoints for user authentication and account management. It supports methods for user login, account creation, account verification, and account deletion.

### Base URL

The base URL for all API endpoints is `https://vt.jo-dev.net/`.  
Endpoints need to be provided as "action" GET parameter (?action=)

## Authentication

All endpoints except for `login`, `createAccount`, and `verifyAccount` require authentication. The authentication token must be included in the `Auth` header of the request.

## Endpoints

### 1. `login`

- **Description**: Logs in a user and returns an authentication token if successful.
- **Method**: `POST`
- **Parameters**:
  - `email` (string, required): The email address of the user.
  - `password` (string, required): The password of the user.
- **Response**:
  - `token` (string): Authentication token.
  - `userData` (object): User data including `userID`, `firstName`, `lastName`, `email`, `modePreference`, and `class`.
- **Errors**:
  - `400`: Missing information or invalid credentials.
  - `401`: Unauthorized or account not verified.

### 2. `createAccount`

- **Description**: Creates a new user account.
- **Method**: `POST`
- **Parameters**:
  - `firstName` (string, required): The first name of the user.
  - `lastName` (string, required): The last name of the user.
  - `email` (string, required): The email address of the user.
  - `password` (string, required): The password of the user.
  - `modePreference` (string, required): The mode preference of the user.
  - `class` (string, required): The class of the user.
- **Response**:
  - `Error` (string): Empty if successful.
- **Errors**:
  - `400`: Missing information or account with email already exists.

### 3. `verifyAccount`

- **Description**: Verifies a user account using a verification code.
- **Method**: `POST`
- **Parameters**:
  - `email` (string, required): The email address of the user.
  - `code` (string, required): The verification code.
- **Response**:
  - `token` (string): Authentication token.
- **Errors**:
  - `400`: Missing information.
  - `401`: Code and email not matching.

### 4. `deleteAccount`

- **Description**: Deletes a user account.
- **Method**: `POST`
- **Parameters**:
  - `password` (string, required): The password of the user.
- **Headers**:
  - `Auth` (string, required): Authentication token.
- **Response**:
  - `Error` (string): Empty if successful.
- **Errors**:
  - `400`: Missing information.
  - `401`: Invalid login credentials.

## Error Handling

The API returns appropriate HTTP status codes and error messages for different scenarios. Refer to each endpoint's description for details on possible errors.

## Authorization

Endpoints that require authentication must include the authentication token in the `Auth` header of the request.

## Example

```bash
curl -X POST https://vt.jo-dev.net/?action=login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'
```
