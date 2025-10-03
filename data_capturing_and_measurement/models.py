from datetime import datetime
from pymongo import MongoClient, ASCENDING
from config import Config
import bcrypt

client = MongoClient(Config.MONGODB_URI)
db = client.get_database()

users_collection = db.users
blacklist_collection = db.token_blacklist
otp_collection = db.otp_codes

users_collection.create_index([("email", ASCENDING)], unique=True)
blacklist_collection.create_index([("token", ASCENDING)], unique=True)
blacklist_collection.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
otp_collection.create_index([("email", ASCENDING)])
otp_collection.create_index([("created_at", ASCENDING)], expireAfterSeconds=600)

class User:
    @staticmethod
    def create(email, password=None, google_id=None, role='user'):
        user_data = {
            'email': email.lower(),
            'role': role,
            'is_active': False if password else True,
            'is_blocked': False,
            'google_id': google_id,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        if password:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_data['password'] = hashed

        result = users_collection.insert_one(user_data)
        user_data['_id'] = result.inserted_id
        return user_data

    @staticmethod
    def find_by_email(email):
        return users_collection.find_one({'email': email.lower()})

    @staticmethod
    def find_by_id(user_id):
        from bson import ObjectId
        return users_collection.find_one({'_id': ObjectId(user_id)})

    @staticmethod
    def find_by_google_id(google_id):
        return users_collection.find_one({'google_id': google_id})

    @staticmethod
    def verify_password(stored_password, provided_password):
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

    @staticmethod
    def update(email, update_fields):
        update_fields['updated_at'] = datetime.utcnow()
        return users_collection.update_one(
            {'email': email.lower()},
            {'$set': update_fields}
        )

    @staticmethod
    def update_by_id(user_id, update_fields):
        from bson import ObjectId
        update_fields['updated_at'] = datetime.utcnow()
        return users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_fields}
        )

    @staticmethod
    def delete_by_id(user_id):
        from bson import ObjectId
        return users_collection.delete_one({'_id': ObjectId(user_id)})

    @staticmethod
    def get_all_users():
        return list(users_collection.find())

class TokenBlacklist:
    @staticmethod
    def add(token, expires_at):
        blacklist_collection.insert_one({
            'token': token,
            'expires_at': expires_at,
            'created_at': datetime.utcnow()
        })

    @staticmethod
    def is_blacklisted(token):
        return blacklist_collection.find_one({'token': token}) is not None

class OTP:
    @staticmethod
    def create(email, code):
        otp_collection.delete_many({'email': email.lower()})
        otp_collection.insert_one({
            'email': email.lower(),
            'code': code,
            'created_at': datetime.utcnow()
        })

    @staticmethod
    def verify(email, code):
        otp = otp_collection.find_one({
            'email': email.lower(),
            'code': code
        })
        if otp:
            otp_collection.delete_one({'_id': otp['_id']})
            return True
        return False

    @staticmethod
    def delete_for_email(email):
        otp_collection.delete_many({'email': email.lower()})
