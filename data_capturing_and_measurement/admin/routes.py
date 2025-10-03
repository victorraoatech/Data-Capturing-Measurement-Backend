from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from admin import admin_bp
from models import User
from utils.decorators import admin_required
import logging

logger = logging.getLogger(__name__)

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    try:
        users = User.get_all_users()

        users_list = []
        for user in users:
            users_list.append({
                'id': str(user['_id']),
                'email': user.get('email'),
                'role': user.get('role', 'user'),
                'is_active': user.get('is_active', False),
                'is_blocked': user.get('is_blocked', False),
                'created_at': user.get('created_at').isoformat() if user.get('created_at') else None
            })

        return jsonify({'users': users_list}), 200

    except Exception as e:
        logger.error(f"Get all users error: {str(e)}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@admin_bp.route('/block-user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required
def block_user(user_id):
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_blocked'):
            return jsonify({'error': 'User is already blocked'}), 400

        User.update_by_id(user_id, {'is_blocked': True})
        logger.info(f"User blocked by admin: {user.get('email')}")

        return jsonify({'message': 'User blocked successfully'}), 200

    except Exception as e:
        logger.error(f"Block user error: {str(e)}")
        return jsonify({'error': 'Failed to block user'}), 500

@admin_bp.route('/unblock-user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required
def unblock_user(user_id):
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.get('is_blocked'):
            return jsonify({'error': 'User is not blocked'}), 400

        User.update_by_id(user_id, {'is_blocked': False})
        logger.info(f"User unblocked by admin: {user.get('email')}")

        return jsonify({'message': 'User unblocked successfully'}), 200

    except Exception as e:
        logger.error(f"Unblock user error: {str(e)}")
        return jsonify({'error': 'Failed to unblock user'}), 500

@admin_bp.route('/reactivate-user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required
def reactivate_user(user_id):
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('is_active'):
            return jsonify({'error': 'User account is already active'}), 400

        User.update_by_id(user_id, {'is_active': True})
        logger.info(f"User reactivated by admin: {user.get('email')}")

        return jsonify({'message': 'User account reactivated successfully'}), 200

    except Exception as e:
        logger.error(f"Reactivate user error: {str(e)}")
        return jsonify({'error': 'Failed to reactivate user'}), 500

@admin_bp.route('/delete-user/<user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    try:
        admin_id = get_jwt_identity()
        if admin_id == user_id:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        User.delete_by_id(user_id)
        logger.info(f"User deleted by admin: {user.get('email')}")

        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500

@admin_bp.route('/promote-user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required
def promote_user(user_id):
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('role') == 'admin':
            return jsonify({'error': 'User is already an admin'}), 400

        User.update_by_id(user_id, {'role': 'admin'})
        logger.info(f"User promoted to admin: {user.get('email')}")

        return jsonify({'message': 'User promoted to admin successfully'}), 200

    except Exception as e:
        logger.error(f"Promote user error: {str(e)}")
        return jsonify({'error': 'Failed to promote user'}), 500

@admin_bp.route('/demote-user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required
def demote_user(user_id):
    try:
        admin_id = get_jwt_identity()
        if admin_id == user_id:
            return jsonify({'error': 'Cannot demote yourself'}), 400

        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('role') != 'admin':
            return jsonify({'error': 'User is not an admin'}), 400

        User.update_by_id(user_id, {'role': 'user'})
        logger.info(f"Admin demoted to user: {user.get('email')}")

        return jsonify({'message': 'User demoted successfully'}), 200

    except Exception as e:
        logger.error(f"Demote user error: {str(e)}")
        return jsonify({'error': 'Failed to demote user'}), 500
