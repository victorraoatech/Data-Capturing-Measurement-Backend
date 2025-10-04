# API Testing Guide

This guide provides step-by-step instructions for testing all endpoints of the Data Capturing and Measurement API.

## Prerequisites

Before testing, ensure:
1. MongoDB Atlas is configured and connection string is in `.env`
2. Gmail SMTP credentials are configured in `.env`
3. Application is running: `python app.py`
4. Server is accessible at `http://localhost:5000`

## Test Flow

### Step 1: Health Check

```bash
curl http://localhost:5000/health
```

Expected: `{"status": "healthy"}`

---

### Step 2: User Signup

```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPass123"
  }'
```

Expected:
```json
{
  "message": "User registered successfully. Please check your email for OTP verification.",
  "email": "testuser@example.com"
}
```

**Action Required:** Check email inbox for OTP code.

---

### Step 3: Verify OTP

Replace `123456` with the actual OTP from email:

```bash
curl -X POST http://localhost:5000/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "otp": "123456"
  }'
```

Expected: `{"message": "Account verified successfully"}`

---

### Step 4: Login

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPass123"
  }'
```

Expected:
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1Qi...",
  "refresh_token": "eyJ0eXAiOiJKV1Qi...",
  "user": {
    "email": "testuser@example.com",
    "role": "user"
  }
}
```

**Important:** Save the `access_token` and `refresh_token` for subsequent requests.

---

### Step 5: Access Protected Profile Route

Replace `<ACCESS_TOKEN>` with your actual token:

```bash
curl -X GET http://localhost:5000/auth/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Expected:
```json
{
  "email": "testuser@example.com",
  "role": "user",
  "is_active": true,
  "is_blocked": false,
  "created_at": "2024-01-15T10:30:00"
}
```

---

### Step 6: Refresh Token

Replace `<REFRESH_TOKEN>` with your actual refresh token:

```bash
curl -X POST http://localhost:5000/auth/refresh \
  -H "Authorization: Bearer <REFRESH_TOKEN>"
```

Expected:
```json
{
  "access_token": "eyJ0eXAiOiJKV1Qi..."
}
```

---

### Step 7: Test Forgot Password

```bash
curl -X POST http://localhost:5000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com"
  }'
```

Expected: `{"message": "Password reset code sent to your email"}`

**Action Required:** Check email for password reset OTP.

---

### Step 8: Reset Password

Replace `123456` with actual OTP:

```bash
curl -X POST http://localhost:5000/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "otp": "123456",
    "new_password": "NewTestPass456"
  }'
```

Expected: `{"message": "Password reset successful"}`

---

### Step 9: Login with New Password

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "NewTestPass456"
  }'
```

**Save the new tokens.**

---

### Step 10: Test Account Deactivation

```bash
curl -X POST http://localhost:5000/auth/deactivate \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewTestPass456"
  }'
```

Expected: `{"message": "Account deactivated successfully"}`

---

### Step 11: Attempt Login After Deactivation

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "NewTestPass456"
  }'
```

Expected: `{"error": "Please verify your account first"}` (403 status)

---

## Admin Testing

### Step 1: Create Admin User

First, create a regular user following Steps 2-4 above with email `admin@example.com`.

Then, manually promote to admin in MongoDB:

```javascript
// In MongoDB Atlas or Compass
db.users.updateOne(
  { email: "admin@example.com" },
  { $set: { role: "admin" } }
)
```

Login as admin:

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "AdminPass123"
  }'
```

**Save the admin access token as `<ADMIN_TOKEN>`.**

---

### Step 2: Get All Users

```bash
curl -X GET http://localhost:5000/admin/users \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: List of all users.

---

### Step 3: Block a User

Get the user ID from Step 2, then:

```bash
curl -X POST http://localhost:5000/admin/block-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User blocked successfully"}`

---

### Step 4: Verify Blocked User Cannot Login

Try logging in as the blocked user:

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "NewTestPass456"
  }'
```

Expected: `{"error": "Account is blocked"}` (403 status)

---

### Step 5: Unblock User

```bash
curl -X POST http://localhost:5000/admin/unblock-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User unblocked successfully"}`

---

### Step 6: Reactivate User

For the deactivated user from earlier:

```bash
curl -X POST http://localhost:5000/admin/reactivate-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User account reactivated successfully"}`

---

### Step 7: Promote User to Admin

```bash
curl -X POST http://localhost:5000/admin/promote-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User promoted to admin successfully"}`

---

### Step 8: Demote Admin to User

```bash
curl -X POST http://localhost:5000/admin/demote-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User demoted successfully"}`

---

### Step 9: Delete User

```bash
curl -X DELETE http://localhost:5000/admin/delete-user/<USER_ID> \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

Expected: `{"message": "User deleted successfully"}`

---

### Step 10: Test Logout

```bash
curl -X POST http://localhost:5000/auth/logout \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Expected: `{"message": "Logout successful"}`

---

### Step 11: Verify Token is Blacklisted

Try using the same token:

```bash
curl -X GET http://localhost:5000/auth/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Expected: `{"error": "Token has been revoked"}` (401 status)

---

## Google OAuth Testing

### Step 1: Get Google Authorization URL

```bash
curl http://localhost:5000/auth/google-login
```

Expected:
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

### Step 2: Complete OAuth Flow

1. Open the `auth_url` in a browser
2. Sign in with Google
3. Grant permissions
4. Get redirected to callback with tokens

The callback will return access and refresh tokens automatically.

---

## Testing Validation

### Invalid Email Format

```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid-email",
    "password": "TestPass123"
  }'
```

Expected: `{"error": "Invalid email format"}` (400 status)

---

### Weak Password

```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "weak"
  }'
```

Expected: Password validation error (400 status)

---

### Duplicate Email

Try signing up with an existing email:

```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPass123"
  }'
```

Expected: `{"error": "Email already registered"}` (409 status)

---

### Missing Authorization Header

```bash
curl -X GET http://localhost:5000/auth/profile
```

Expected: `{"error": "Authorization token is missing"}` (401 status)

---

### Invalid Token

```bash
curl -X GET http://localhost:5000/auth/profile \
  -H "Authorization: Bearer invalid_token_here"
```

Expected: `{"error": "Invalid token"}` (401 status)

---

### Non-Admin Accessing Admin Routes

Login as regular user and try:

```bash
curl -X GET http://localhost:5000/admin/users \
  -H "Authorization: Bearer <USER_ACCESS_TOKEN>"
```

Expected: `{"error": "Admin access required"}` (403 status)

---

## Postman Collection

You can import these endpoints into Postman:

1. Create a new Collection: "Data Capturing API"
2. Add environment variables:
   - `BASE_URL`: `http://localhost:5000`
   - `ACCESS_TOKEN`: (will be set after login)
   - `REFRESH_TOKEN`: (will be set after login)
   - `ADMIN_TOKEN`: (will be set after admin login)

3. Add requests with proper headers and bodies as shown above

---

## Success Criteria

All tests pass when:
- ✅ Users can signup and receive OTP
- ✅ OTP verification activates accounts
- ✅ Login returns valid JWT tokens
- ✅ Protected routes require valid tokens
- ✅ Token refresh works correctly
- ✅ Password reset flow works
- ✅ Account deactivation prevents login
- ✅ Blocked users cannot login or refresh tokens
- ✅ Admin can manage all users
- ✅ Google OAuth creates/logs in users
- ✅ Token blacklisting works on logout
- ✅ Input validation catches errors
- ✅ All error responses are appropriate

---

## Troubleshooting

**MongoDB Connection Error:**
- Check MONGODB_URI in .env
- Verify IP whitelist in MongoDB Atlas
- Test connection string separately

**Email Not Sending:**
- Verify MAIL_PASSWORD is App Password, not regular password
- Check Gmail 2-Step Verification is enabled
- Look at app.log for error details

**Token Errors:**
- Ensure JWT_SECRET_KEY is set in .env
- Check token hasn't expired (1 hour for access, 30 days for refresh)
- Verify token format: `Bearer <token>`

**Import Errors:**
- Run: `pip install -r requirements.txt`
- Activate virtual environment
- Check Python version (3.8+)
