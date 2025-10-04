# Swagger API Documentation Setup

This document explains the Swagger/OpenAPI integration for the Data Capturing and Measurement API.

## Overview

The API is now fully documented using Flasgger (Flask + Swagger). The interactive Swagger UI is available at `/apidocs`.

## Installation

The required dependency has been added to `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Configuration

### 1. Swagger Configuration (`swagger_config.py`)

This file contains the Swagger configuration and metadata:

- **API Information**: Title, description, version
- **Security Definitions**: JWT Bearer token authentication
- **Tags**: Organized by Authentication, Admin, and Health
- **Base Configuration**: Swagger UI settings

### 2. Flask App Integration (`app.py`)

Flasgger is initialized in the `create_app()` function:

```python
from flasgger import Swagger
from swagger_config import swagger_config, swagger_template

Swagger(app, config=swagger_config, template=swagger_template)
```

### 3. Route Documentation

Each route has comprehensive YAML documentation in its docstring that includes:

- **Tags**: Categorize endpoints
- **Parameters**: Request body schemas, path parameters, headers
- **Responses**: All possible HTTP status codes with examples
- **Security**: JWT authentication requirements
- **Examples**: Sample request/response data

## Accessing the Documentation

1. Start your Flask application:
   ```bash
   cd data_capturing_and_measurement
   python app.py
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:5000/apidocs
   ```

3. You'll see the interactive Swagger UI with all documented endpoints.

## Using the Swagger UI

### Testing Authenticated Endpoints

1. First, register and login using the `/auth/signup` and `/auth/login` endpoints
2. Copy the `access_token` from the login response
3. Click the **Authorize** button at the top of the Swagger UI
4. Enter: `Bearer YOUR_ACCESS_TOKEN` (replace YOUR_ACCESS_TOKEN with your actual token)
5. Click **Authorize**
6. Now you can test protected endpoints

### Example Workflow

1. **Register**: POST `/auth/signup`
   ```json
   {
     "email": "user@example.com",
     "password": "SecurePass123!"
   }
   ```

2. **Verify OTP**: POST `/auth/verify-otp`
   ```json
   {
     "email": "user@example.com",
     "otp": "123456"
   }
   ```

3. **Login**: POST `/auth/login`
   ```json
   {
     "email": "user@example.com",
     "password": "SecurePass123!"
   }
   ```

4. **Authorize**: Use the access_token from login response

5. **Get Profile**: GET `/auth/profile` (requires authentication)

6. **Admin Operations**: GET `/admin/users` (requires admin role)

## API Endpoints Overview

### Authentication Endpoints (`/auth`)

- `POST /auth/signup` - Register a new user
- `POST /auth/verify-otp` - Verify account with OTP
- `POST /auth/resend-otp` - Resend OTP code
- `POST /auth/login` - Login with email and password
- `POST /auth/logout` - Logout and revoke token
- `POST /auth/refresh` - Refresh access token
- `GET /auth/profile` - Get user profile
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password with OTP
- `POST /auth/deactivate` - Deactivate account

### Admin Endpoints (`/admin`)

- `GET /admin/users` - Get all users (admin only)
- `POST /admin/block-user/<user_id>` - Block a user
- `POST /admin/unblock-user/<user_id>` - Unblock a user
- `POST /admin/reactivate-user/<user_id>` - Reactivate user account
- `DELETE /admin/delete-user/<user_id>` - Delete a user
- `POST /admin/promote-user/<user_id>` - Promote user to admin
- `POST /admin/demote-user/<user_id>` - Demote admin to user

### Health Endpoints

- `GET /` - API welcome message
- `GET /health` - Health check

## Customization

### Updating API Metadata

Edit `swagger_config.py` to change:
- API title, description, version
- Host and base path
- Contact information
- Security schemes
- Tags and descriptions

### Adding New Endpoints

To document a new endpoint, add a docstring to your route function:

```python
@app.route('/new-endpoint', methods=['POST'])
def new_endpoint():
    """
    Endpoint Title
    ---
    tags:
      - Tag Name
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
        description: Success response
        schema:
          type: object
          properties:
            message:
              type: string
              example: Success
    """
    # Your endpoint logic
```

## OpenAPI Specification

The OpenAPI specification JSON is available at:
```
http://localhost:5000/apispec.json
```

This can be imported into tools like Postman, Insomnia, or other API clients.

## Production Deployment

For production deployment, update the `host` field in `swagger_config.py`:

```python
"host": "api.yourdomain.com",
"schemes": ["https"],
```

## Troubleshooting

### Swagger UI not loading
- Check that `flasgger` is installed: `pip list | grep -i flasgger`
- Ensure `swagger_config.py` is in the same directory as `app.py`
- Check browser console for JavaScript errors

### Endpoints not showing
- Verify docstrings are properly formatted with `---` separator
- Check that the route is registered with the Flask app
- Restart the Flask application

### Authentication not working
- Ensure you're using `Bearer YOUR_TOKEN` format
- Check token hasn't expired (default: 15 minutes for access token)
- Use refresh token endpoint to get a new access token

## Additional Resources

- [Flasgger Documentation](https://github.com/flasgger/flasgger)
- [OpenAPI Specification](https://swagger.io/specification/)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)
