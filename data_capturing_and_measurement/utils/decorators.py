from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask import jsonify
from models import User
import logging

logger = logging.getLogger(__name__)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)

        if not user:
            logger.warning(f"Admin access attempt with invalid user_id: {user_id}")
            return jsonify({'error': 'User not found'}), 404

        if user.get('role') != 'admin':
            logger.warning(f"Unauthorized admin access attempt by user: {user.get('email')}")
            return jsonify({'error': 'Admin access required'}), 403

        return fn(*args, **kwargs)
    return wrapper

def active_user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_blocked'):
            logger.warning(f"Blocked user access attempt: {user.get('email')}")
            return jsonify({'error': 'Account is blocked'}), 403

        if not user.get('is_active'):
            return jsonify({'error': 'Account is not active'}), 403

        return fn(*args, **kwargs)
    return wrapper
