# Swagger Integration - Complete Code Examples

This document provides the complete production-ready code for Swagger/OpenAPI integration.

## File Structure

```
data_capturing_and_measurement/
├── app.py                    # Main Flask app (updated with Swagger)
├── swagger_config.py         # NEW: Swagger configuration
├── requirements.txt          # Updated with flasgger
├── auth/
│   └── routes.py            # Updated with Swagger docs
└── admin/
    └── routes.py            # Updated with Swagger docs
```

---

## 1. swagger_config.py (NEW FILE)

```python
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Data Capturing and Measurement API",
        "description": "A comprehensive API for user authentication, authorization, and management with JWT tokens, OTP verification, and admin capabilities.",
        "version": "1.0.0",
        "contact": {
            "name": "API Support",
            "email": "support@datacapture.com"
        }
    },
    "host": "localhost:5000",
    "basePath": "/",
    "schemes": ["http", "https"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
        }
    },
    "tags": [
        {
            "name": "Authentication",
            "description": "User authentication and account management endpoints"
        },
        {
            "name": "Admin",
            "description": "Admin-only endpoints for user management (requires admin role)"
        },
        {
            "name": "Health",
            "description": "Health check and status endpoints"
        }
    ]
}
```

---

## 2. app.py (UPDATED - Key Changes)

### Import Changes

```python
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flasgger import Swagger  # NEW
from config import Config
from models import TokenBlacklist
from swagger_config import swagger_config, swagger_template  # NEW
import logging
```

### Swagger Initialization

```python
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)

    jwt = JWTManager(app)
    mail = Mail(app)

    # Initialize Swagger - NEW
    Swagger(app, config=swagger_config, template=swagger_template)

    # ... rest of the code
```

### Example Documented Endpoint

```python
@app.route('/')
def index():
    """
    API Welcome Endpoint
    ---
    tags:
      - Health
    responses:
      200:
        description: Welcome message with API information
        schema:
          type: object
          properties:
            message:
              type: string
              example: Welcome to Data Capturing and Measurement API
            version:
              type: string
              example: 1.0.0
            endpoints:
              type: object
              properties:
                auth:
                  type: string
                  example: /auth
                admin:
                  type: string
                  example: /admin
    """
    return jsonify({
        'message': 'Welcome to Data Capturing and Measurement API',
        'version': '1.0.0',
        'endpoints': {
            'auth': '/auth',
            'admin': '/admin'
        }
    }), 200
```

---

## 3. auth/routes.py Example Documentation

### POST /auth/signup

```python
@auth_bp.route('/signup', methods=['POST'])
def signup():
    """
    Register a new user
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              format: email
              example: user@example.com
              description: User's email address
            password:
              type: string
              format: password
              example: SecurePass123!
              description: User's password (min 8 characters, must include uppercase, lowercase, number, and special character)
    responses:
      201:
        description: User registered successfully, OTP sent to email
        schema:
          type: object
          properties:
            message:
              type: string
              example: User registered successfully. Please check your email for OTP verification.
            email:
              type: string
              example: user@example.com
      400:
        description: Bad request (invalid email or password format)
        schema:
          type: object
          properties:
            error:
              type: string
              example: Invalid email format
      409:
        description: Email already registered
        schema:
          type: object
          properties:
            error:
              type: string
              example: Email already registered
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: Registration failed
    """
    try:
        # ... existing signup code ...
```

### POST /auth/login

```python
@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login with email and password
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              format: email
              example: user@example.com
              description: User's email address
            password:
              type: string
              format: password
              example: SecurePass123!
              description: User's password
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            message:
              type: string
              example: Login successful
            access_token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            refresh_token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            user:
              type: object
              properties:
                email:
                  type: string
                  example: user@example.com
                role:
                  type: string
                  example: user
      400:
        description: Bad request (missing fields)
        schema:
          type: object
          properties:
            error:
              type: string
              example: Email and password are required
      401:
        description: Invalid credentials
        schema:
          type: object
          properties:
            error:
              type: string
              example: Invalid credentials
      403:
        description: Account not verified or blocked
        schema:
          type: object
          properties:
            error:
              type: string
              example: Please verify your account first
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: Login failed
    """
    try:
        # ... existing login code ...
```

### GET /auth/profile (Authenticated Endpoint)

```python
@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
@active_user_required
def profile():
    """
    Get authenticated user profile
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: User profile retrieved successfully
        schema:
          type: object
          properties:
            email:
              type: string
              example: user@example.com
            role:
              type: string
              example: user
            is_active:
              type: boolean
              example: true
            is_blocked:
              type: boolean
              example: false
            created_at:
              type: string
              format: date-time
              example: "2025-10-04T12:00:00"
      401:
        description: Unauthorized (missing or invalid token)
        schema:
          type: object
          properties:
            error:
              type: string
              example: Authorization token is missing
      404:
        description: User not found
        schema:
          type: object
          properties:
            error:
              type: string
              example: User not found
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: Failed to fetch profile
    """
    try:
        # ... existing profile code ...
```

---

## 4. admin/routes.py Example Documentation

### GET /admin/users

```python
@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    """
    Get all users (Admin only)
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: List of all users retrieved successfully
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                    example: 507f1f77bcf86cd799439011
                  email:
                    type: string
                    example: user@example.com
                  role:
                    type: string
                    example: user
                  is_active:
                    type: boolean
                    example: true
                  is_blocked:
                    type: boolean
                    example: false
                  created_at:
                    type: string
                    format: date-time
                    example: "2025-10-04T12:00:00"
      401:
        description: Unauthorized (missing or invalid token)
        schema:
          type: object
          properties:
            error:
              type: string
              example: Authorization token is missing
      403:
        description: Forbidden (user is not an admin)
        schema:
          type: object
          properties:
            error:
              type: string
              example: Admin access required
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: Failed to fetch users
    """
    try:
        # ... existing code ...
```

---

## 5. requirements.txt (UPDATED)

```
Flask==3.0.0
Flask-JWT-Extended==4.6.0
Flask-Mail==0.9.1
Flask-Cors==4.0.0
pymongo[srv,tls]>=4.5.0
bcrypt==4.1.2
python-dotenv==1.0.0
Authlib==1.3.0
requests==2.31.0
dnspython==2.4.2
flasgger==0.9.7.1
```

---

## Installation and Usage

### 1. Install Dependencies

```bash
cd data_capturing_and_measurement
pip install -r requirements.txt
```

### 2. Start the Application

```bash
python app.py
```

### 3. Access Swagger UI

Open your browser and navigate to:
```
http://localhost:5000/apidocs
```

### 4. Test Endpoints

1. Use the Swagger UI to test the `/auth/signup` endpoint
2. Verify your account with `/auth/verify-otp`
3. Login using `/auth/login` and copy the access_token
4. Click the **Authorize** button (top right) and enter: `Bearer YOUR_TOKEN`
5. Test protected endpoints like `/auth/profile` or `/admin/users`

---

## Key Features

1. **Interactive API Testing**: Test all endpoints directly from the browser
2. **Automatic Documentation**: All endpoints are automatically documented
3. **JWT Authentication**: Integrated Bearer token authentication
4. **Request/Response Examples**: Clear examples for all endpoints
5. **Error Handling**: Comprehensive error response documentation
6. **Tags and Organization**: Endpoints grouped by functionality
7. **Production Ready**: Clean, maintainable code structure

---

## Customization Guide

### Adding New Endpoints

To document a new endpoint, add a docstring with YAML:

```python
@your_bp.route('/your-endpoint', methods=['POST'])
@jwt_required()  # If authentication is required
def your_function():
    """
    Your endpoint description
    ---
    tags:
      - Your Tag
    security:
      - Bearer: []  # If authentication is required
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            field_name:
              type: string
              example: example value
    responses:
      200:
        description: Success
        schema:
          type: object
          properties:
            result:
              type: string
    """
    # Your code here
```

### Updating API Metadata

Edit `swagger_config.py`:
- Change title, description, version
- Update contact information
- Modify host for production deployment
- Add or remove tags

---

## Production Deployment

For production, update `swagger_config.py`:

```python
swagger_template = {
    # ...
    "host": "api.yourdomain.com",  # Your production domain
    "schemes": ["https"],           # Use HTTPS only
    # ...
}
```

---

This completes the Swagger integration! Your Flask API now has professional, interactive documentation at `/apidocs`.
