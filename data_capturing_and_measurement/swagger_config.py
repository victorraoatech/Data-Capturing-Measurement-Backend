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
