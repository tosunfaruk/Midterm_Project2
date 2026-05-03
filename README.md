# Secure Auth API

A secure Python-based backend system demonstrating robust authentication flows and Role-Based Access Control (RBAC).

## Project Objective
This project simulates a secure backend environment utilizing JSON Web Tokens (JWT) for identity verification and authorization. It emphasizes the "Principle of Least Privilege", ensuring standard users cannot access privileged routes or tamper with their assigned roles.

## Features
- **Secure Password Storage:** Passwords are never stored in plain text. They are salted and securely hashed using the `bcrypt` library.
- **JWT Issuance & Validation:** Successful authentication generates a stateless JWT containing the user identity and role. Protected endpoints intercept requests to validate the token signature and expiration.
- **Role-Based Routing (RBAC):** Implements distinct access levels. `GET /profile` is accessible to all authenticated users, while `DELETE /user/{id}` is strictly restricted to the Admin role.
- **Token Revocation (Blacklisting):** A `/logout` feature that intercepts the JWT and adds it to a database blacklist, invalidating the token server-side before its natural expiry.
- **Defensive Logging:** Custom middleware logs all `403 Forbidden` unauthorized access attempts to a local `security.log` file, including timestamps and HTTP methods.

## Tech Stack
- **Framework:** FastAPI
- **Authentication:** PyJWT, bcrypt
- **Database:** SQLite

## Installation & Setup
1. Clone the repository and navigate into the project directory.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
   ```
3. Install the required dependencies:
   ```bash
   pip install fastapi uvicorn bcrypt PyJWT pydantic python-multipart
   ```
4. Run the development server:
   ```bash
   uvicorn main:app --reload
   ```
5. Navigate to `http://127.0.0.1:8000/docs` in your browser to test the endpoints interactively via Swagger UI.
