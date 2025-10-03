from flask import request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from auth import auth_bp
from models import User, TokenBlacklist, OTP
from utils.validators import validate_email, validate_password, validate_required_fields
from utils.email_sender import send_otp_email, send_password_reset_email
from utils.decorators import active_user_required
import random
import string
import logging
import bcrypt
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

@auth_bp.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email', 'password'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()
        password = data['password']

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        valid, msg = validate_password(password)
        if not valid:
            return jsonify({'error': msg}), 400

        if User.find_by_email(email):
            return jsonify({'error': 'Email already registered'}), 409

        user = User.create(email=email, password=password)
        logger.info(f"User created: {email}")

        otp_code = generate_otp()
        OTP.create(email, otp_code)

        mail = current_app.extensions.get('mail')
        if mail and send_otp_email(mail, email, otp_code):
            return jsonify({
                'message': 'User registered successfully. Please check your email for OTP verification.',
                'email': email
            }), 201
        else:
            return jsonify({
                'message': 'User registered but failed to send OTP email. Please request a new OTP.',
                'email': email
            }), 201

    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email', 'otp'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()
        otp_code = data['otp'].strip()

        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_active'):
            return jsonify({'error': 'Account already verified'}), 400

        if OTP.verify(email, otp_code):
            User.update(email, {'is_active': True})
            logger.info(f"Account verified: {email}")
            return jsonify({'message': 'Account verified successfully'}), 200
        else:
            return jsonify({'error': 'Invalid or expired OTP'}), 400

    except Exception as e:
        logger.error(f"OTP verification error: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()

        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_active'):
            return jsonify({'error': 'Account already verified'}), 400

        otp_code = generate_otp()
        OTP.create(email, otp_code)

        mail = current_app.extensions.get('mail')
        if mail and send_otp_email(mail, email, otp_code):
            logger.info(f"OTP resent to: {email}")
            return jsonify({'message': 'OTP sent successfully'}), 200
        else:
            return jsonify({'error': 'Failed to send OTP'}), 500

    except Exception as e:
        logger.error(f"Resend OTP error: {str(e)}")
        return jsonify({'error': 'Failed to resend OTP'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email', 'password'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()
        password = data['password']

        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.get('password'):
            return jsonify({'error': 'Please use Google login'}), 401

        if not User.verify_password(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.get('is_active'):
            return jsonify({'error': 'Please verify your account first'}), 403

        if user.get('is_blocked'):
            logger.warning(f"Blocked user login attempt: {email}")
            return jsonify({'error': 'Account is blocked'}), 403

        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))

        logger.info(f"User logged in: {email}")

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'email': user['email'],
                'role': user.get('role', 'user')
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_blocked'):
            return jsonify({'error': 'Account is blocked'}), 403

        if not user.get('is_active'):
            return jsonify({'error': 'Account is not active'}), 403

        access_token = create_access_token(identity=user_id)
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        exp = get_jwt()['exp']
        expires_at = datetime.fromtimestamp(exp)

        TokenBlacklist.add(jti, expires_at)

        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)
        if user:
            logger.info(f"User logged out: {user.get('email')}")

        return jsonify({'message': 'Logout successful'}), 200

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()

        user = User.find_by_email(email)
        if not user:
            return jsonify({'message': 'If the email exists, a reset code will be sent'}), 200

        if not user.get('password'):
            return jsonify({'error': 'Please use Google login'}), 400

        otp_code = generate_otp()
        OTP.create(email, otp_code)

        mail = current_app.extensions.get('mail')
        if mail and send_password_reset_email(mail, email, otp_code):
            logger.info(f"Password reset OTP sent to: {email}")
            return jsonify({'message': 'Password reset code sent to your email'}), 200
        else:
            return jsonify({'error': 'Failed to send reset code'}), 500

    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'error': 'Password reset request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['email', 'otp', 'new_password'])
        if not valid:
            return jsonify({'error': msg}), 400

        email = data['email'].strip()
        otp_code = data['otp'].strip()
        new_password = data['new_password']

        valid, msg = validate_password(new_password)
        if not valid:
            return jsonify({'error': msg}), 400

        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not OTP.verify(email, otp_code):
            return jsonify({'error': 'Invalid or expired OTP'}), 400

        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        User.update(email, {'password': hashed})

        logger.info(f"Password reset successful: {email}")
        return jsonify({'message': 'Password reset successful'}), 200

    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
@active_user_required
def profile():
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'email': user['email'],
            'role': user.get('role', 'user'),
            'is_active': user.get('is_active', False),
            'is_blocked': user.get('is_blocked', False),
            'created_at': user.get('created_at').isoformat() if user.get('created_at') else None
        }), 200

    except Exception as e:
        logger.error(f"Profile fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@auth_bp.route('/deactivate', methods=['POST'])
@jwt_required()
@active_user_required
def deactivate_account():
    try:
        data = request.get_json()

        valid, msg = validate_required_fields(data, ['password'])
        if not valid:
            return jsonify({'error': msg}), 400

        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('password') and not User.verify_password(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401

        User.update_by_id(user_id, {'is_active': False})
        logger.info(f"Account deactivated: {user.get('email')}")

        return jsonify({'message': 'Account deactivated successfully'}), 200

    except Exception as e:
        logger.error(f"Account deactivation error: {str(e)}")
        return jsonify({'error': 'Failed to deactivate account'}), 500
