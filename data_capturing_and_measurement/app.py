from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flasgger import Swagger
from config import Config
from models import TokenBlacklist
from swagger_config import swagger_config, swagger_template
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)

    jwt = JWTManager(app)
    mail = Mail(app)

    Swagger(app, config=swagger_config, template=swagger_template)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return TokenBlacklist.is_blacklisted(jti)

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has expired',
            'message': 'Please login again'
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'Invalid token',
            'message': 'Please provide a valid token'
        }), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'Authorization token is missing',
            'message': 'Please provide a valid token'
        }), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has been revoked',
            'message': 'Please login again'
        }), 401

    from auth import auth_bp
    from auth import google_auth
    from admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

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

    @app.route('/health')
    def health():
        """
        Health Check Endpoint
        ---
        tags:
          - Health
        responses:
          200:
            description: API health status
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: healthy
        """
        return jsonify({'status': 'healthy'}), 200

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500

    logger.info("Application started successfully")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
