# Data Capturing and Measurement

A complete Flask-based authentication and account management system with MongoDB Atlas integration.

## Features

### Authentication
- **Signup with Email & Password** - Users register and receive OTP for verification
- **Email Verification** - OTP-based account activation via Gmail SMTP
- **Login** - Email/password authentication with JWT tokens
- **JWT Access & Refresh Tokens** - Secure token-based authentication
- **Logout** - Token blacklisting for secure logout
- **Forgot/Reset Password** - OTP-based password recovery
- **Google OAuth2** - Sign in/up with Google accounts

### Account Management
- **User Profile** - View account details
- **Account Deactivation** - Users can deactivate their own accounts
- **Account Blocking** - Admin can block/unblock users
- **Account Reactivation** - Admin can reactivate deactivated accounts

### Admin Controls
- **User Management** - View all users
- **Block/Unblock Users** - Control user access
- **Delete Users** - Permanent user removal
- **Reactivate Accounts** - Restore deactivated accounts
- **Role Management** - Promote/demote users to admin

## Project Structure

```
data_capturing_and_measurement/
├── app.py                 # Application entry point
├── config.py             # Configuration settings
├── models.py             # MongoDB models
├── requirements.txt      # Python dependencies
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore rules
├── README.md            # This file
├── auth/                # Authentication blueprint
│   ├── __init__.py
│   ├── routes.py        # Auth endpoints
│   └── google_auth.py   # Google OAuth implementation
├── admin/               # Admin blueprint
│   ├── __init__.py
│   └── routes.py        # Admin endpoints
└── utils/               # Utility modules
    ├── __init__.py
    ├── validators.py    # Input validation
    ├── email_sender.py  # Email utilities
    └── decorators.py    # Custom decorators
```

## Setup Instructions

### Prerequisites
- Python 3.8+
- MongoDB Atlas account
- Gmail account for sending emails (with App Password)
- Google Cloud Console project (for OAuth)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd data_capturing_and_measurement
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` and fill in your credentials:

```env
JWT_SECRET_KEY=your_secure_random_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_DEFAULT_SENDER=your_gmail@gmail.com
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname?retryWrites=true&w=majority
```

#### Setting Up Gmail App Password:
1. Go to Google Account Settings
2. Enable 2-Step Verification
3. Generate App Password for "Mail"
4. Use the generated password in `MAIL_PASSWORD`

#### Setting Up MongoDB Atlas:
1. Create account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a cluster
3. Add database user
4. Whitelist your IP address
5. Get connection string and add to `MONGODB_URI`

#### Setting Up Google OAuth:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:5000/auth/google-callback`
6. Copy Client ID and Client Secret to `.env`

### 5. Run the Application

```bash
python app.py
```

The server will start on `http://localhost:5000`

## API Endpoints

### Authentication Endpoints

#### POST `/auth/signup`
Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "User registered successfully. Please check your email for OTP verification.",
  "email": "user@example.com"
}
```

#### POST `/auth/verify-otp`
Verify email with OTP code.

**Request:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "message": "Account verified successfully"
}
```

#### POST `/auth/resend-otp`
Resend OTP verification code.

**Request:**
```json
{
  "email": "user@example.com"
}
```

#### POST `/auth/login`
Login with email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### POST `/auth/refresh`
Get new access token using refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

#### POST `/auth/logout`
Logout and blacklist token.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

#### POST `/auth/forgot-password`
Request password reset OTP.

**Request:**
```json
{
  "email": "user@example.com"
}
```

#### POST `/auth/reset-password`
Reset password with OTP.

**Request:**
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "new_password": "NewSecurePass123"
}
```

#### GET `/auth/google-login`
Initiate Google OAuth login.

**Response:**
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

#### GET `/auth/google-callback`
Google OAuth callback (handled automatically).

#### GET `/auth/profile`
Get user profile (protected route).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "email": "user@example.com",
  "role": "user",
  "is_active": true,
  "is_blocked": false,
  "created_at": "2024-01-15T10:30:00"
}
```

#### POST `/auth/deactivate`
Deactivate own account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "password": "SecurePass123"
}
```

### Admin Endpoints (Require Admin Role)

#### GET `/admin/users`
Get all users.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### POST `/admin/block-user/<user_id>`
Block a user.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### POST `/admin/unblock-user/<user_id>`
Unblock a user.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### POST `/admin/reactivate-user/<user_id>`
Reactivate a deactivated account.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### DELETE `/admin/delete-user/<user_id>`
Delete a user permanently.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### POST `/admin/promote-user/<user_id>`
Promote user to admin.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

#### POST `/admin/demote-user/<user_id>`
Demote admin to user.

**Headers:**
```
Authorization: Bearer <admin_access_token>
```

## Testing Locally

### Using cURL

**1. Sign up:**
```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}'
```

**2. Verify OTP (check your email):**
```bash
curl -X POST http://localhost:5000/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","otp":"123456"}'
```

**3. Login:**
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}'
```

**4. Access protected route:**
```bash
curl -X GET http://localhost:5000/auth/profile \
  -H "Authorization: Bearer <your_access_token>"
```

### Using Postman

1. Import the endpoints into Postman
2. Set `Authorization` header to `Bearer <token>` for protected routes
3. Test each endpoint sequentially

## Security Features

- **Password Hashing** - bcrypt for secure password storage
- **JWT Tokens** - Secure authentication with access and refresh tokens
- **Token Blacklisting** - Revoked tokens stored in MongoDB
- **OTP Verification** - Time-limited OTP codes (10 minutes)
- **Input Validation** - Email format and password strength validation
- **Role-Based Access** - Admin and user roles with proper authorization
- **Account Blocking** - Prevent access for blocked users
- **CORS Protection** - Cross-origin resource sharing enabled

## Logging

All major actions are logged:
- User registration
- Login/logout
- OTP sending
- Password resets
- Admin actions (block/unblock/delete)

Logs are saved to `app.log` and console output.

## Creating First Admin User

After the first user is created, you need to manually promote them to admin via MongoDB:

1. Connect to your MongoDB Atlas cluster
2. Find the user document
3. Update the `role` field to `"admin"`

```javascript
db.users.updateOne(
  { email: "admin@example.com" },
  { $set: { role: "admin" } }
)
```

## Troubleshooting

### Email not sending
- Verify Gmail App Password is correct
- Check if 2-Step Verification is enabled
- Ensure less secure app access is not blocking

### MongoDB connection issues
- Verify connection string format
- Check if IP address is whitelisted
- Confirm database user credentials

### Google OAuth not working
- Verify redirect URI matches exactly
- Check if Google+ API is enabled
- Confirm Client ID and Secret are correct

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first.
