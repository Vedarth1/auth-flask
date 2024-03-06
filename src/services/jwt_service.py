# jwt_service.py
import jwt
import os
from datetime import datetime

def generate_token(user):
    payload = {
        'iat': datetime.utcnow(),
        'user_id': str(user.id).replace('-', ""),
        'firstname': user.firstname,
        'lastname': user.lastname,
        'email': user.email,
    }
    token = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')
    return token
