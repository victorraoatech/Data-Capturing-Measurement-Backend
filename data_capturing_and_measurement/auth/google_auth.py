from flask import request, jsonify, current_app, url_for
from flask_jwt_extended import create_access_token, create_refresh_token
from auth import auth_bp
from models import User
import requests
import logging

logger = logging.getLogger(__name__)

def get_google_provider_cfg():
    from config import Config
    return requests.get(Config.GOOGLE_DISCOVERY_URL).json()

@auth_bp.route('/google-login', methods=['GET'])
def google_login():
    try:
        from config import Config

        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
            return jsonify({'error': 'Google OAuth not configured'}), 500

        google_provider_cfg = get_google_provider_cfg()
        authorization_endpoint = google_provider_cfg['authorization_endpoint']

        redirect_uri = url_for('auth.google_callback', _external=True)

        params = {
            'client_id': Config.GOOGLE_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': 'openid email profile',
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': 'select_account'
        }

        auth_url = f"{authorization_endpoint}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"

        return jsonify({'auth_url': auth_url}), 200

    except Exception as e:
        logger.error(f"Google login initiation error: {str(e)}")
        return jsonify({'error': 'Failed to initiate Google login'}), 500

@auth_bp.route('/google-callback', methods=['GET'])
def google_callback():
    try:
        from config import Config

        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'Authorization code not provided'}), 400

        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg['token_endpoint']

        redirect_uri = url_for('auth.google_callback', _external=True)

        token_data = {
            'code': code,
            'client_id': Config.GOOGLE_CLIENT_ID,
            'client_secret': Config.GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }

        token_response = requests.post(token_endpoint, data=token_data)
        tokens = token_response.json()

        if 'error' in tokens:
            logger.error(f"Google token error: {tokens.get('error_description')}")
            return jsonify({'error': 'Failed to obtain access token'}), 400

        userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
        headers = {'Authorization': f"Bearer {tokens['access_token']}"}
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        userinfo = userinfo_response.json()

        google_id = userinfo['sub']
        email = userinfo.get('email')

        if not email:
            return jsonify({'error': 'Email not provided by Google'}), 400

        user = User.find_by_google_id(google_id)

        if not user:
            user = User.find_by_email(email)
            if user:
                User.update(email, {'google_id': google_id})
                logger.info(f"Google ID linked to existing user: {email}")
            else:
                user = User.create(email=email, google_id=google_id)
                logger.info(f"New user created via Google: {email}")

        if user.get('is_blocked'):
            return jsonify({'error': 'Account is blocked'}), 403

        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))

        logger.info(f"User logged in via Google: {email}")

        return jsonify({
            'message': 'Google login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'email': user.get('email'),
                'role': user.get('role', 'user')
            }
        }), 200

    except Exception as e:
        logger.error(f"Google callback error: {str(e)}")
        return jsonify({'error': 'Google login failed'}), 500
